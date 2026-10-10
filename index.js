require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const multer     = require('multer');
const pool       = require('./db');

// Crash-proofing: log errors instead of dying
process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT:', err.message);
  if (err.stack) console.error(err.stack.split('\n')[1]);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 UNHANDLED:', reason && reason.message || reason);
});

const nodemailer   = require('nodemailer');
const speakeasy    = require('speakeasy');
const { OAuth2Client } = require('google-auth-library');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const qrcode       = require('qrcode');

/* ---------- mailer (Gmail SMTP) ---------- */
const mailer = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: { rejectUnauthorized: false }
});

// verify connection once at startup
mailer.verify((err) => {
  if (err) console.error('❌ SMTP verify failed:', err.message);
  else console.log('✅ SMTP ready');
});

function makeToken(){
  return require('crypto').randomBytes(24).toString('hex');
}

async function sendVerificationEmail(toEmail, token, displayName){
  const baseUrl = process.env.APP_URL || 'http://localhost:3000';
  const link = baseUrl + '/verify?token=' + token;
  const info = await mailer.sendMail({
    from: '"GistApp" <' + process.env.SMTP_USER + '>',
    to: toEmail,
    replyTo: process.env.SMTP_USER,
    subject: 'Verify your GistApp account',
    headers: {
      'X-Priority': '1',
      'X-MSMail-Priority': 'High',
      'Importance': 'high',
      'List-Unsubscribe': '<mailto:' + process.env.SMTP_USER + '>'
    },
    html: `
      <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#f7f5ff;border-radius:20px">
        <h2 style="color:#33344c;margin:0 0 16px">Hi ${displayName || 'there'} 👋</h2>
        <p style="color:#4a4568;font-size:15px;line-height:1.6">
          Welcome to GistApp! Tap the button below to verify your email address and activate your account.
        </p>
        <div style="text-align:center;margin:28px 0">
          <a href="${link}" style="background:#33344c;color:#fff;text-decoration:none;padding:14px 32px;border-radius:14px;font-weight:700;display:inline-block">
            Verify my email
          </a>
        </div>
        <p style="color:#8e8e93;font-size:13px;line-height:1.6">
          Or copy this link into your browser:<br>
          <span style="color:#6a62b8;word-break:break-all">${link}</span>
        </p>
        <p style="color:#8e8e93;font-size:12px;margin-top:24px">
          If you didn't sign up for GistApp, just ignore this email.
        </p>
      </div>
    `
  });
  return info;
}


const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const onlineUsers = new Map();

/* ---------- uploads ---------- */
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req,_file,cb)=>cb(null, uploadDir),
  filename: (_req,file,cb)=>cb(null, Date.now()+'-'+Math.random().toString(36).slice(2,8)+path.extname(file.originalname||''))
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- helpers ---------- */
function auth(req,res,next){
  const h = req.headers.authorization||'';
  const token = h.startsWith('Bearer ')?h.slice(7):null;
  if (!token) return res.status(401).json({error:'No token'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({error:'Invalid token'}); }
}
const sign = u => jwt.sign({id:u.id,email:u.email}, JWT_SECRET, {expiresIn:'30d'});

async function isMember(chatId,userId){ const r = await pool.query('SELECT status,is_admin,muted,archived,favorite FROM chat_members WHERE chat_id=$1 AND user_id=$2',[chatId,userId]); return r.rows[0]; }
async function isAdmin(chatId,userId){ const r = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND is_admin=true",[chatId,userId]); return r.rowCount>0; }

/* ---------- google social login ---------- */
app.post('/api/auth/google', async (req,res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase();
    const name  = payload.name || email.split('@')[0];
    const gid   = payload.sub;
    if (!email) return res.status(400).json({ error: 'No email from Google' });
    let user = (await pool.query('SELECT * FROM users WHERE email=$1',[email])).rows[0];
    if (!user){
      const r = await pool.query(
        'INSERT INTO users (email, password_hash, display_name, verified, google_id, onboarded) VALUES ($1,$2,$3,true,$4,false) RETURNING id,email,display_name,avatar_color,dark_mode,font_size,onboarded',
        [email, 'google-oauth', name, gid]
      );
      user = r.rows[0];
    } else {
      await pool.query('UPDATE users SET google_id=$1, verified=true WHERE id=$2', [gid, user.id]);
    }
    await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[user.id]);
    res.json({
      user: { id: user.id, email: user.email, display_name: user.display_name,
        avatar_color: user.avatar_color, dark_mode: user.dark_mode,
        font_size: user.font_size, onboarded: user.onboarded },
      token: sign(user),
      isNew: !user.onboarded
    });
  } catch(e){
    console.error('google auth error:', e.message);
    res.status(401).json({ error: 'Google sign-in failed' });
  }
});

app.post('/api/onboard', auth, async (req,res) => {
  try {
    const { display_name, bio, avatar_url } = req.body;
    const sets=[]; const vals=[]; let i=1;
    if (display_name){ sets.push(`display_name=$${i++}`); vals.push(display_name); }
    if (bio){ sets.push(`bio=$${i++}`); vals.push(bio); }
    if (avatar_url){ sets.push(`avatar_url=$${i++}`); vals.push(avatar_url); }
    sets.push(`onboarded=true`);
    vals.push(req.user.id);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,email,display_name,avatar_color,avatar_url,bio,onboarded`,
      vals
    );
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- auth ---------- */
app.post('/api/signup', async (req,res)=>{
  try {
    const { email, password, display_name } = req.body;
    if (!email || !password) return res.status(400).json({error:'Email and password required'});
    const exists = await pool.query('SELECT id FROM users WHERE email=$1',[email.toLowerCase()]);
    if (exists.rowCount) return res.status(409).json({error:'Email already registered'});
    const hash = await bcrypt.hash(password,10);
    const name = display_name || email.split('@')[0];
    const vtoken = makeToken();
    const vexpires = new Date(Date.now() + 24 * 3600 * 1000);
    const r = await pool.query(
      'INSERT INTO users (email,password_hash,display_name,verified,verify_token,verify_expires) VALUES ($1,$2,$3,false,$4,$5) RETURNING id,email,display_name,avatar_color,dark_mode,font_size',
      [email.toLowerCase(), hash, name, vtoken, vexpires]
    );
    // Respond IMMEDIATELY — do not wait for SMTP
    res.json({
      user: r.rows[0],
      token: sign(r.rows[0]),
      needsVerification: true,
      emailSent: true,
      emailError: null
    });

    // Send the email in the background (fire-and-forget)
    sendVerificationEmail(email.toLowerCase(), vtoken, name)
      .then(() => console.log('✅ Verification email sent to', email.toLowerCase()))
      .catch(mailErr => console.error('❌ Email send failed:', mailErr.message));
  } catch(e){ console.error(e); res.status(500).json({error:'Server error'}); }
});
app.post('/api/login', async (req,res)=>{
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);
    if (!r.rowCount) return res.status(401).json({error:'Invalid credentials'});
    const user = r.rows[0];
    if (!await bcrypt.compare(password,user.password_hash)) return res.status(401).json({error:'Invalid credentials'});
    if (user.verified === false) {
      return res.status(403).json({
        error: 'Please verify your email first — check your inbox for the link.',
        needsVerification: true
      });
    }
    await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[user.id]);
    res.json({
      user: {
        id: user.id, email: user.email, display_name: user.display_name,
        avatar_color: user.avatar_color, dark_mode: user.dark_mode, font_size: user.font_size
      },
      token: sign(user)
    });
  } catch(e){ console.error(e); res.status(500).json({error:'Server error'}); }
});
app.get('/api/me', auth, async (req,res)=>{
  const r = await pool.query('SELECT id,email,display_name,username,avatar_color,dark_mode,font_size,blocked_ids,prefs,avatar_url,cover_url,bio,totp_enabled,onboarded,onboard_stage,birthday,interests,follows,joined_communities,permissions,pin_hash,app_lock_enabled,app_lock_timeout_min,chat_lock_enabled,locked_chats FROM users WHERE id=$1',[req.user.id]);
  res.json(r.rows[0]);
});
app.patch('/api/me', auth, async (req,res)=>{
  const { display_name, avatar_color, dark_mode, font_size, dnd_until, prefs, avatar_url, cover_url, bio } = req.body;
  const sets=[],vals=[]; let i=1;
  if (display_name!==undefined){sets.push(`display_name=$${i++}`);vals.push(display_name);}
  if (avatar_color!==undefined){sets.push(`avatar_color=$${i++}`);vals.push(avatar_color);}
  if (dark_mode!==undefined){sets.push(`dark_mode=$${i++}`);vals.push(!!dark_mode);}
  if (font_size!==undefined){sets.push(`font_size=$${i++}`);vals.push(font_size);}
  if (dnd_until!==undefined){sets.push(`dnd_until=$${i++}`);vals.push(dnd_until);}
  if (avatar_url!==undefined){sets.push(`avatar_url=$${i++}`);vals.push(avatar_url);}
  if (cover_url!==undefined){sets.push(`cover_url=$${i++}`);vals.push(cover_url);}
  if (bio!==undefined){sets.push(`bio=$${i++}`);vals.push(bio);}
  if (prefs!==undefined){
    const existing = await pool.query('SELECT prefs FROM users WHERE id=$1',[req.user.id]);
    const merged = Object.assign({}, existing.rows[0].prefs||{}, prefs);
    sets.push(`prefs=$${i++}`); vals.push(merged);
  }
  if (!sets.length) return res.json({ok:true});
  vals.push(req.user.id);
  const r = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id,email,display_name,avatar_color,dark_mode,font_size,dnd_until,prefs,avatar_url,cover_url,bio`,[...vals]);
  res.json(r.rows[0]);
});

/* ---------- USERNAME + ONBOARDING ---------- */
app.get('/api/username/suggest', auth, async (req, res) => {
  try {
    const base = (req.query.base || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 15) || 'user';
    const suggestions = [];
    let attempts = 0;
    while (suggestions.length < 5 && attempts < 40){
      attempts++;
      let candidate;
      const r = Math.random();
      if (r < 0.33) candidate = base + Math.floor(Math.random() * 9000 + 1000);
      else if (r < 0.66) candidate = base + '_' + Math.floor(Math.random() * 900 + 100);
      else candidate = base + Math.floor(Math.random() * 99 + 1);
      const exists = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=$1', [candidate]);
      if (!exists.rowCount && !suggestions.includes(candidate)) suggestions.push(candidate);
    }
    res.json({ base, suggestions });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/username/set', auth, async (req, res) => {
  try {
    const u = String(req.body.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return res.status(400).json({ error: '3-20 chars, a-z, 0-9, _ only' });
    const taken = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=$1 AND id<>$2', [u, req.user.id]);
    if (taken.rowCount) return res.status(409).json({ error: 'Username already taken' });
    await pool.query('UPDATE users SET username=$1 WHERE id=$2', [u, req.user.id]);
    res.json({ ok: true, username: u });
  } catch(e){ console.error('username error:', e.message); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/onboard/profile', auth, async (req, res) => {
  try {
    const { display_name, bio, avatar_url, birthday } = req.body;
    const sets=[]; const vals=[]; let i=1;
    if (display_name){ sets.push('display_name=$' + (i++)); vals.push(display_name); }
    if (bio){ sets.push('bio=$' + (i++)); vals.push(bio); }
    if (avatar_url){ sets.push('avatar_url=$' + (i++)); vals.push(avatar_url); }
    if (birthday){
      const dob = new Date(birthday);
      const age = Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 3600 * 1000));
      if (age < 18) return res.status(403).json({ error: 'You must be at least 18' });
      sets.push('birthday=$' + (i++)); vals.push(birthday);
    }
    sets.push('onboard_stage=GREATEST(onboard_stage, 1)');
    vals.push(req.user.id);
    const r = await pool.query('UPDATE users SET ' + sets.join(', ') + ' WHERE id=$' + i + ' RETURNING id,email,display_name,username,avatar_color,avatar_url,bio,birthday,onboard_stage', vals);
    res.json(r.rows[0]);
  } catch(e){ console.error('onboard profile:', e.message); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/onboard/interests', auth, async (req, res) => {
  try {
    const list = (req.body.interests || []).slice(0, 20).map(String);
    const r = await pool.query('UPDATE users SET interests=$1::jsonb, onboard_stage=GREATEST(onboard_stage, 2) WHERE id=$2 RETURNING interests, onboard_stage', [JSON.stringify(list), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/onboard/picks', auth, async (req, res) => {
  try {
    const follows = (req.body.follows || []).slice(0, 50).map(String);
    const joined = (req.body.joined_communities || []).slice(0, 50).map(String);
    const r = await pool.query('UPDATE users SET follows=$1::jsonb, joined_communities=$2::jsonb, onboard_stage=GREATEST(onboard_stage, 3) WHERE id=$3 RETURNING follows, joined_communities, onboard_stage', [JSON.stringify(follows), JSON.stringify(joined), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/onboard/permissions', auth, async (req, res) => {
  try {
    const perms = {
      notifications: !!(req.body.permissions && req.body.permissions.notifications),
      find_friends: !!(req.body.permissions && req.body.permissions.find_friends)
    };
    const r = await pool.query('UPDATE users SET permissions=$1::jsonb, onboard_stage=4, onboarded=true WHERE id=$2 RETURNING permissions, onboard_stage, onboarded', [JSON.stringify(perms), req.user.id]);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- chats list ---------- */

async function isBlockedBetween(aId, bId){
  try {
    const r = await pool.query(
      'SELECT blocked_ids FROM users WHERE id=$1',
      [aId]
    );
    let list = (r.rows[0] && r.rows[0].blocked_ids); if (!Array.isArray(list)) list = [];
    return list.map(Number).includes(Number(bId));
  } catch(_){ return false; }
}

/* ---------- avatar visibility ---------- */
/* Generic visibility check — used for bio, status, last_seen, groups */
async function canViewField(viewerId, ownerId, prefKey){
  if (Number(viewerId) === Number(ownerId)) return true;
  try {
    const r = await pool.query('SELECT prefs FROM users WHERE id=$1', [ownerId]);
    if (!r.rowCount) return false;
    const vis = (r.rows[0].prefs && r.rows[0].prefs[prefKey]) || 'Everyone';
    if (vis === 'Everyone') return true;
    if (vis === 'Nobody') return false;
    if (vis === 'My contacts'){
      const c = await pool.query(`
        SELECT 1 FROM chats ch
        JOIN chat_members a ON a.chat_id=ch.id AND a.user_id=$1
        JOIN chat_members b ON b.chat_id=ch.id AND b.user_id=$2
        WHERE ch.type='dm' LIMIT 1
      `, [ownerId, viewerId]);
      return c.rowCount > 0;
    }
    return false;
  } catch(_){ return false; }
}

async function canViewPhoto(viewerId, ownerId){
  if (Number(viewerId) === Number(ownerId)) return true;
  try {
    const r = await pool.query('SELECT prefs, avatar_url FROM users WHERE id=$1',[ownerId]);
    if (!r.rowCount) return false;
    const owner = r.rows[0];
    if (!owner.avatar_url) return false;
    const vis = (owner.prefs && owner.prefs.profile_photo) || 'Everyone';
    if (vis === 'Everyone') return true;
    if (vis === 'Nobody')   return false;
    if (vis === 'My contacts'){
      const c = await pool.query(`
        SELECT 1 FROM chats ch
        JOIN chat_members a ON a.chat_id=ch.id AND a.user_id=$1
        JOIN chat_members b ON b.chat_id=ch.id AND b.user_id=$2
        WHERE ch.type='dm' LIMIT 1
      `,[ownerId,viewerId]);
      return c.rowCount > 0;
    }
    return false;
  } catch(_){ return false; }
}

app.get('/api/chats', auth, async (req,res)=>{
  const r = await pool.query(`
    SELECT c.id,c.type,c.name,c.description,c.icon_emoji,
      m.status AS my_status, m.muted, m.archived, m.favorite,
      (SELECT body FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_at,
      (SELECT COUNT(*) FROM messages WHERE chat_id=c.id AND sender_id<>$1 AND deleted_at IS NULL AND created_at > COALESCE(m.last_read_at,'1970-01-01')) AS unread,
      o.id AS other_id, o.display_name AS other_name, o.email AS other_email, o.avatar_color AS other_color,
      o.avatar_url   AS other_url,
      o.last_seen_at AS other_last_seen,
      om.status AS other_status,
      (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) AS member_count
    FROM chats c
    JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1 AND m.status='accepted'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1 AND c.type='dm'
    LEFT JOIN users o ON o.id=om.user_id
    ORDER BY m.favorite DESC, m.archived ASC, COALESCE(
      (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1), c.created_at) DESC
  `,[req.user.id]);

  // Enforce visibility prefs per chat
  const rows = await Promise.all(r.rows.map(async c => {
    if (c.other_id){
      if (c.other_url){
        const ok = await canViewPhoto(req.user.id, c.other_id);
        if (!ok) c.other_url = null;
      }
      if (c.other_last_seen){
        const ok = await canViewField(req.user.id, c.other_id, 'last_seen');
        if (!ok) c.other_last_seen = null;
      }
    }
    return c;
  }));
  res.json(rows);
});

/* ---------- requests ---------- */
app.get('/api/requests', auth, async (req,res)=>{
  const r = await pool.query(`
    SELECT c.id AS chat_id, c.type, c.name, u.id AS user_id, u.display_name, u.email, u.avatar_color, u.avatar_url, c.created_at
    FROM chats c
    JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1 AND m.status='pending'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1
    LEFT JOIN users u ON u.id=om.user_id
    ORDER BY c.created_at DESC
  `,[req.user.id]);
  const rows = await Promise.all(r.rows.map(async x => {
    if (x.avatar_url && x.user_id){
      const ok = await canViewPhoto(req.user.id, x.user_id);
      if (!ok) x.avatar_url = null;
    }
    return x;
  }));
  res.json(rows);
});
app.post('/api/requests/:id/accept', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const r = await pool.query("UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2 AND status='pending' RETURNING chat_id",[chatId,req.user.id]);
  if (!r.rowCount) return res.status(404).json({error:'No pending request'});
  const others = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2',[chatId,req.user.id]);
  others.rows.forEach(row=>io.to('user:'+row.user_id).emit('chats-changed'));
  res.json({ok:true});
});
app.post('/api/requests/:id/decline', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const r = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='pending'",[chatId,req.user.id]);
  if (!r.rowCount) return res.status(404).json({error:'No pending request'});
  await pool.query('DELETE FROM chats WHERE id=$1',[chatId]);
  res.json({ok:true});
});

/* ---------- start DM / group ---------- */
app.post('/api/chats/dm', auth, async (req,res)=>{
  const { email } = req.body;
  const other = await pool.query('SELECT id FROM users WHERE email=$1',[String(email||'').toLowerCase()]);
  if (!other.rowCount) return res.status(404).json({error:'User not found'});
  const otherId = other.rows[0].id;
  if (otherId === req.user.id) return res.status(400).json({error:'Cannot chat with yourself'});
  const existing = await pool.query(`SELECT c.id, a.status AS my_status FROM chats c JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1 JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2 WHERE c.type='dm' LIMIT 1`,[req.user.id,otherId]);
  if (existing.rowCount){
    const row = existing.rows[0];
    if (row.my_status==='pending'){
      await pool.query("UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2",[row.id,req.user.id]);
      io.to('user:'+otherId).emit('chats-changed');
    }
    return res.json({chat_id:row.id});
  }
  const chat = await pool.query("INSERT INTO chats (type) VALUES ('dm') RETURNING id");
  const chatId = chat.rows[0].id;
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'accepted'),($1,$3,'pending')",[chatId,req.user.id,otherId]);
  io.to('user:'+otherId).emit('requests-changed');
  res.json({chat_id:chatId});
});
app.post('/api/chats/group', auth, async (req,res)=>{
  const { name, emails } = req.body;
  if (!name||!name.trim()) return res.status(400).json({error:'Group name required'});
  const list = (emails||[]).map(e=>String(e).trim().toLowerCase()).filter(Boolean);
  if (!list.length) return res.status(400).json({error:'Add at least one member'});
  const users = await pool.query('SELECT id,email FROM users WHERE email = ANY($1)',[list]);
  if (users.rowCount !== list.length){
    const found = users.rows.map(r=>r.email);
    return res.status(404).json({error:'Not registered: '+list.filter(e=>!found.includes(e)).join(', ')});
  }
  const chat = await pool.query("INSERT INTO chats (type,name) VALUES ('group',$1) RETURNING id",[name.trim()]);
  const chatId = chat.rows[0].id;
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status,last_read_at,is_admin) VALUES ($1,$2,'accepted',NOW(),true)",[chatId,req.user.id]);
  for (const u of users.rows){
    await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending')",[chatId,u.id]);
    io.to('user:'+u.id).emit('requests-changed');
  }
  res.json({chat_id:chatId});
});
app.post('/api/chats/:id/members', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  if (!await isMember(chatId,req.user.id)) return res.status(403).json({error:'Not a member'});
  const u = await pool.query('SELECT id FROM users WHERE email=$1',[String(req.body.email||'').toLowerCase()]);
  if (!u.rowCount) return res.status(404).json({error:'User not found'});
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending') ON CONFLICT DO NOTHING",[chatId,u.rows[0].id]);
  io.to('user:'+u.rows[0].id).emit('requests-changed');
  res.json({ok:true});
});

/* ---------- chat settings ---------- */
app.patch('/api/chats/:id', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  const { name, description, icon_emoji, muted, archived, favorite } = req.body;
  if ((name!==undefined||description!==undefined||icon_emoji!==undefined) && m.status==='accepted'){
    const sets=[],vals=[];let i=1;
    if (name!==undefined){sets.push(`name=$${i++}`);vals.push(name);}
    if (description!==undefined){sets.push(`description=$${i++}`);vals.push(description);}
    if (icon_emoji!==undefined){sets.push(`icon_emoji=$${i++}`);vals.push(icon_emoji);}
    if (sets.length){ vals.push(chatId); await pool.query(`UPDATE chats SET ${sets.join(', ')} WHERE id=$${i}`,[...vals]); }
  }
  const msets=[],mvals=[];let j=1;
  if (muted!==undefined){msets.push(`muted=$${j++}`);mvals.push(!!muted);}
  if (req.body.pinned!==undefined){msets.push(`pinned=$${j++}`);mvals.push(!!req.body.pinned);}
  if (req.body.unread!==undefined){msets.push(`unread=$${j++}`);mvals.push(!!req.body.unread);}
  if (archived!==undefined){msets.push(`archived=$${j++}`);mvals.push(!!archived);}
  if (favorite!==undefined){msets.push(`favorite=$${j++}`);mvals.push(!!favorite);}
  if (msets.length){ mvals.push(chatId); mvals.push(req.user.id); await pool.query(`UPDATE chat_members SET ${msets.join(', ')} WHERE chat_id=$${j} AND user_id=$${j+1}`,[...mvals]); }
  res.json({ok:true});
});

/* ---------- delete chat ---------- */
app.delete('/api/chats/:id', auth, async (req,res)=>{
  const chatId = Number(req.params.id);
  if (!await isMember(chatId,req.user.id)) return res.status(403).json({error:'Not a member'});
  await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2',[chatId,req.user.id]);
  res.json({ok:true});
});

/* ---------- messages ---------- */
app.get('/api/chats/:id/messages', auth, async (req,res)=>{
  const chatId = req.params.id;
  const q = (req.query.q||'').trim();
  const filter = req.query.filter || '';
  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  if (m.status !== 'accepted') return res.status(403).json({error:'Chat not accepted yet'});

  const params = [chatId];
  let where = 'WHERE m.chat_id=$1';
  if (q){ params.push('%'+q.toLowerCase()+'%'); where += ` AND LOWER(m.body) LIKE $${params.length}`; }
  if (filter==='media') where += ' AND m.media_url IS NOT NULL';
  if (filter==='starred'){ params.push(req.user.id); where += ` AND m.starred_by ? $${params.length}`; }
  if (filter==='links') where += ` AND m.body ~* 'https?://'`;

  const r = await pool.query(`
    SELECT m.id, m.body, m.created_at, m.edited_at, m.sender_id, m.reactions, m.read_at,
           m.media_url, m.media_type, m.deleted_at, m.starred_by, m.pinned, m.reply_to_id,
           u.display_name, u.avatar_color, u.avatar_url,
           (SELECT body FROM messages WHERE id=m.reply_to_id) AS reply_body,
           (SELECT sender_id FROM messages WHERE id=m.reply_to_id) AS reply_sender_id,
           (SELECT display_name FROM users WHERE id=(SELECT sender_id FROM messages WHERE id=m.reply_to_id)) AS reply_sender
    FROM messages m JOIN users u ON u.id=m.sender_id
    ${where}
    ORDER BY m.pinned DESC, m.created_at ASC LIMIT 300
  `, params);

  // get my block list once
  let myBlocks = (await pool.query('SELECT blocked_ids FROM users WHERE id=$1',[req.user.id])).rows[0].blocked_ids; if (!Array.isArray(myBlocks)) myBlocks = [];
  const myBlockSet = new Set(myBlocks.map(Number));

  // Enforce avatar visibility + filter blocked
  const msgs = await Promise.all(r.rows.map(async m => {
    // hide messages from blocked users
    if (myBlockSet.has(Number(m.sender_id))) return null;
    // hide avatar if not permitted
    if (m.avatar_url && m.sender_id !== req.user.id){
      const ok = await canViewPhoto(req.user.id, m.sender_id);
      if (!ok) m.avatar_url = null;
    }
    return m;
  }));
  res.json(msgs.filter(Boolean));
});

app.post('/api/chats/:id/messages', auth, async (req,res)=>{
  const chatId = req.params.id;
  const { body, media_url, media_type, reply_to_id } = req.body;
  const text = (body||'').trim();
  if (!text && !media_url) return res.status(400).json({error:'Empty message'});
  const m = await isMember(chatId,req.user.id);
  if (!m) return res.status(403).json({error:'Not a member'});
  if (m.status!=='accepted') return res.status(403).json({error:'Chat not accepted yet'});

  // block enforcement
  const other = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2 LIMIT 1', [chatId, req.user.id]);
  if (other.rowCount){
    const them = other.rows[0].user_id;
    if (await isBlockedBetween(them, req.user.id)){
      return res.status(403).json({ error: 'You cannot message this user' });
    }
  }

  let row;
  if (text && !reply_to_id){
    const dup = await pool.query("SELECT id,body,created_at,sender_id,reactions,read_at,media_url,media_type,reply_to_id,edited_at,starred_by,pinned FROM messages WHERE chat_id=$1 AND sender_id=$2 AND body=$3 AND deleted_at IS NULL AND created_at > NOW() - INTERVAL '3 seconds' ORDER BY created_at DESC LIMIT 1",[chatId,req.user.id,text]);
    if (dup.rowCount) row = dup.rows[0];
  }
  if (!row){
    // disappearing messages: look up user's preference
    const mePrefsRow = await pool.query('SELECT prefs FROM users WHERE id=$1',[req.user.id]);
    const prefs = (mePrefsRow.rows[0] && mePrefsRow.rows[0].prefs) || {};
    const disp = prefs.disappearing || 'Off';
    let expiresAt = null;
    if (disp === '24 hours') expiresAt = new Date(Date.now() + 24*3600*1000);
    else if (disp === '7 days') expiresAt = new Date(Date.now() + 7*24*3600*1000);
    else if (disp === '90 days') expiresAt = new Date(Date.now() + 90*24*3600*1000);

    const r = await pool.query(
      'INSERT INTO messages (chat_id,sender_id,body,media_url,media_type,reply_to_id,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,body,created_at,sender_id,reactions,read_at,media_url,media_type,reply_to_id,edited_at,starred_by,pinned,expires_at',
      [chatId,req.user.id,text,media_url||null,media_type||null,reply_to_id||null,expiresAt]
    );
    row = r.rows[0];
  }
  const me = await pool.query('SELECT display_name,avatar_color,avatar_url FROM users WHERE id=$1',[req.user.id]);
  const full = {...row, display_name:me.rows[0].display_name, avatar_color:me.rows[0].avatar_color, avatar_url:me.rows[0].avatar_url, chat_id:chatId};
  if (reply_to_id){
    const rp = await pool.query('SELECT body,sender_id,(SELECT display_name FROM users WHERE id=messages.sender_id) AS sender FROM messages WHERE id=$1',[reply_to_id]);
    if (rp.rowCount){ full.reply_body = rp.rows[0].body; full.reply_sender = rp.rows[0].sender; full.reply_sender_id = rp.rows[0].sender_id; }
  }
  io.to('chat:'+chatId).emit('message', full);
  res.json(full);
});

app.patch('/api/messages/:id/edit', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { body } = req.body;
  const m = await pool.query('SELECT sender_id,chat_id FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (m.rows[0].sender_id !== req.user.id) return res.status(403).json({error:'Not yours'});
  await pool.query('UPDATE messages SET body=$1, edited_at=NOW() WHERE id=$2',[String(body||'').trim(),id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-edited',{id, body:String(body||'').trim()});
  res.json({ok:true});
});

app.patch('/api/messages/:id/star', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,starred_by FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const list = m.rows[0].starred_by || [];
  const has = list.includes(req.user.id);
  const next = has ? list.filter(x=>x!==req.user.id) : [...list, req.user.id];
  await pool.query('UPDATE messages SET starred_by=$1 WHERE id=$2',[next,id]);
  res.json({starred:!has});
});

app.patch('/api/messages/:id/pin', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,pinned FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const next = !m.rows[0].pinned;
  await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2',[next,id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-pinned',{id, pinned:next});
  res.json({pinned:next});
});

app.patch('/api/messages/:id/react', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { emoji } = req.body;
  const m = await pool.query('SELECT chat_id,reactions FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(m.rows[0].chat_id,req.user.id)) return res.status(403).json({error:'Not a member'});
  const rx = m.rows[0].reactions || {};
  const arr = Array.isArray(rx[emoji]) ? rx[emoji] : [];
  rx[emoji] = arr.includes(req.user.id) ? arr.filter(x=>x!==req.user.id) : [...arr, req.user.id];
  if (!rx[emoji].length) delete rx[emoji];
  await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2',[rx,id]);
  io.to('chat:'+m.rows[0].chat_id).emit('reaction',{id, reactions:rx});
  res.json({id, reactions:rx});
});

app.delete('/api/messages/:id', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const m = await pool.query('SELECT chat_id,sender_id FROM messages WHERE id=$1',[id]);
  if (!m.rowCount) return res.status(404).json({error:'Not found'});
  if (m.rows[0].sender_id !== req.user.id) return res.status(403).json({error:'Not yours'});
  await pool.query('UPDATE messages SET deleted_at=NOW(), body=NULL, media_url=NULL WHERE id=$1',[id]);
  io.to('chat:'+m.rows[0].chat_id).emit('message-deleted',{id});
  res.json({ok:true});
});

/* ---------- forward ---------- */
app.post('/api/messages/:id/forward', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const { to_chat } = req.body;
  const src = await pool.query('SELECT body,media_url,media_type FROM messages WHERE id=$1',[id]);
  if (!src.rowCount) return res.status(404).json({error:'Not found'});
  if (!await isMember(to_chat,req.user.id)) return res.status(403).json({error:'Not a member of target chat'});
  const r = await pool.query(
    'INSERT INTO messages (chat_id,sender_id,body,media_url,media_type) VALUES ($1,$2,$3,$4,$5) RETURNING id,body,created_at,sender_id,media_url,media_type',
    [to_chat,req.user.id,src.rows[0].body,src.rows[0].media_url,src.rows[0].media_type]
  );
  const me = await pool.query('SELECT display_name,avatar_color,avatar_url FROM users WHERE id=$1',[req.user.id]);
  const full = {...r.rows[0], display_name:me.rows[0].display_name, avatar_color:me.rows[0].avatar_color, chat_id:to_chat};
  io.to('chat:'+to_chat).emit('message',full);
  res.json(full);
});

/* ---------- read ---------- */
app.post('/api/chats/:id/read', auth, async (req,res)=>{
  await pool.query('UPDATE chat_members SET last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2',[req.params.id,req.user.id]);
  await pool.query('UPDATE messages SET read_at=COALESCE(read_at,NOW()) WHERE chat_id=$1 AND sender_id<>$2',[req.params.id,req.user.id]);
  io.to('chat:'+req.params.id).emit('read',{by:req.user.id});
  res.json({ok:true});
});

/* ---------- upload ---------- */
app.post('/api/upload', auth, upload.single('file'), (req,res)=>{
  if (!req.file) return res.status(400).json({error:'No file'});
  const type = req.file.mimetype.startsWith('image/')?'image':req.file.mimetype.startsWith('video/')?'video':req.file.mimetype.startsWith('audio/')?'audio':'file';
  res.json({url:'/uploads/'+req.file.filename, type});
});

/* ---------- block ---------- */
app.post('/api/users/:id/block', auth, async (req,res)=>{
  try {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) return res.status(400).json({ error: 'Invalid user id' });
    const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1',[req.user.id]);
    let list = r.rows[0].blocked_ids;
    if (!Array.isArray(list)) list = [];
    list = list.map(Number);
    const wasBlocked = list.includes(id);
    const next = wasBlocked ? list.filter(x=>x!==id) : [...list, id];
    await pool.query('UPDATE users SET blocked_ids=$1::jsonb WHERE id=$2',[JSON.stringify(next),req.user.id]);
    res.json({blocked: !wasBlocked});
  } catch(e){ console.error('block error', e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- blocked list ---------- */
app.get('/api/blocked', auth, async (req, res) => {
  const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1', [req.user.id]);
  const ids = r.rows[0].blocked_ids || [];
  if (!ids.length) return res.json([]);
  const u = await pool.query(
    'SELECT id, display_name, email, avatar_color, avatar_url FROM users WHERE id = ANY($1)',
    [ids]
  );
  res.json(u.rows);
});

/* ---------- delete my account ---------- */
app.delete('/api/me', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- export my data ---------- */
app.get('/api/export', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT id,email,display_name,avatar_color,dark_mode,font_size,prefs,created_at FROM users WHERE id=$1', [req.user.id]);
    const chats = await pool.query('SELECT c.id,c.type,c.name FROM chats c JOIN chat_members m ON m.chat_id=c.id AND m.user_id=$1', [req.user.id]);
    const messages = await pool.query(`
      SELECT m.id, m.chat_id, m.body, m.created_at, m.media_url, m.media_type, m.deleted_at
      FROM messages m
      JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1
      ORDER BY m.created_at ASC
    `, [req.user.id]);
    res.json({
      exported_at: new Date().toISOString(),
      account: me.rows[0],
      chats: chats.rows,
      messages: messages.rows
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/search', auth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json([]);
    const r = await pool.query(`
      SELECT m.id, m.chat_id, m.body, m.created_at, u.display_name
      FROM messages m
      JOIN users u ON u.id=m.sender_id
      JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1 AND cm.status='accepted'
      WHERE m.deleted_at IS NULL AND LOWER(m.body) LIKE $2
      ORDER BY m.created_at DESC LIMIT 50
    `, [req.user.id, '%' + q.toLowerCase() + '%']);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- two-step verification ---------- */
app.post('/api/2fa/setup', auth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name: 'GistApp (' + req.user.email + ')',
      issuer: 'GistApp'
    });
    const qr = await qrcode.toDataURL(secret.otpauth_url);
    // store secret but DO NOT enable yet — user must verify a code first
    await pool.query('UPDATE users SET totp_secret=$1 WHERE id=$2', [secret.base32, req.user.id]);
    res.json({ secret: secret.base32, qr });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/2fa/enable', auth, async (req, res) => {
  try {
    const { code } = req.body;
    const r = await pool.query('SELECT totp_secret FROM users WHERE id=$1', [req.user.id]);
    const secret = r.rows[0].totp_secret;
    if (!secret) return res.status(400).json({ error: 'Run setup first' });
    const ok = speakeasy.totp.verify({ secret, encoding:'base32', token: String(code||'').trim(), window: 1 });
    if (!ok) return res.status(400).json({ error: 'Invalid code' });
    await pool.query('UPDATE users SET totp_enabled=true WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/2fa/disable', auth, async (req, res) => {
  try {
    const { password } = req.body;
    const r = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    const ok = await bcrypt.compare(String(password||''), r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    await pool.query('UPDATE users SET totp_enabled=false, totp_secret=NULL WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- change email ---------- */
app.post('/api/me/change-email', auth, async (req, res) => {
  try {
    const { password, new_email } = req.body;
    const target = String(new_email||'').toLowerCase().trim();
    if (!target || !target.includes('@')) return res.status(400).json({ error: 'Invalid email' });
    if (target === req.user.email) return res.status(400).json({ error: 'Same as current email' });
    const dup = await pool.query('SELECT id FROM users WHERE email=$1', [target]);
    if (dup.rowCount) return res.status(409).json({ error: 'That email is already in use' });
    const me = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    const ok = await bcrypt.compare(String(password||''), me.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    const token = makeToken();
    const expires = new Date(Date.now() + 24*3600*1000);
    await pool.query(
      'UPDATE users SET email_change_token=$1, email_change_new=$2, email_change_expires=$3 WHERE id=$4',
      [token, target, expires, req.user.id]
    );
    // send verification link to the NEW email
    const baseUrl = process.env.APP_URL || 'http://localhost:3000';
    const link = baseUrl + '/verify-email-change?token=' + token;
    res.json({ ok: true, sent_to: target });
    mailer.sendMail({
      from: '"GistApp" <' + process.env.SMTP_USER + '>',
      to: target,
      subject: 'Confirm your new GistApp email',
      html: '<p>Tap the link below to confirm this email address for your GistApp account:</p>' +
            '<p><a href="' + link + '">' + link + '</a></p>' +
            '<p>Link expires in 24 hours.</p>'
    }).then(() => console.log('✅ Change-email verification sent to', target))
      .catch(mailErr => console.error('❌ Change-email send failed:', mailErr.message));
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/verify-email-change', async (req, res) => {
  const token = (req.query.token||'').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  const r = await pool.query(
    'SELECT id, email_change_new FROM users WHERE email_change_token=$1 AND email_change_expires > NOW()',
    [token]
  );
  if (!r.rowCount) return res.send('<h2>Link expired or invalid</h2>');
  const newEmail = r.rows[0].email_change_new;
  await pool.query(
    'UPDATE users SET email=$1, email_change_token=NULL, email_change_new=NULL, email_change_expires=NULL WHERE id=$2',
    [newEmail, r.rows[0].id]
  );
  res.send('<html><body style="font-family:Inter,sans-serif;text-align:center;padding:60px"><h1 style="color:#25d366">✅ Email updated</h1><p>You can now log in with ' + newEmail + '</p><a href="/">Open GistApp</a></body></html>');
});

/* ---------- resend verification ---------- */
app.post('/api/verify/resend', async (req, res) => {
  try {
    const email = (req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const r = await pool.query('SELECT id, display_name, verified FROM users WHERE email=$1', [email]);
    if (!r.rowCount) return res.status(404).json({ error: 'No account with that email' });
    if (r.rows[0].verified) return res.json({ ok: true, message: 'Already verified' });
    const token = makeToken();
    const expires = new Date(Date.now() + 24 * 3600 * 1000);
    await pool.query('UPDATE users SET verify_token=$1, verify_expires=$2 WHERE id=$3', [token, expires, r.rows[0].id]);
    res.json({ ok: true, message: 'Sending…' });
    sendVerificationEmail(email, token, r.rows[0].display_name)
      .then(() => console.log('✅ Resent verification to', email))
      .catch(e => console.error('❌ Resend failed:', e.message));
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- CALL HISTORY ---------- */
app.get('/api/calls', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.id, c.kind, c.status, c.started_at, c.answered_at, c.ended_at, c.duration_sec,
        c.caller_id, c.callee_id,
        CASE WHEN c.caller_id=$1 THEN c.callee_id ELSE c.caller_id END AS other_id,
        u.display_name AS other_name, u.avatar_color AS other_color, u.avatar_url AS other_url,
        (c.caller_id = $1) AS outgoing
      FROM calls c
      JOIN users u ON u.id = CASE WHEN c.caller_id=$1 THEN c.callee_id ELSE c.caller_id END
      WHERE c.caller_id=$1 OR c.callee_id=$1
      ORDER BY c.started_at DESC LIMIT 100
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/calls/log', auth, async (req, res) => {
  try {
    const { callee_id, kind, status, duration_sec } = req.body;
    if (!callee_id || !kind) return res.status(400).json({ error: 'Missing fields' });
    const r = await pool.query(
      'INSERT INTO calls (caller_id, callee_id, kind, status, answered_at, ended_at, duration_sec) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [req.user.id, callee_id, kind, status || 'ended',
       status === 'answered' ? new Date() : null,
       new Date(), duration_sec || 0]
    );
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- report user ---------- */
app.post('/api/users/:id/report', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    const { reason } = req.body;
    if (!reason || !String(reason).trim()) return res.status(400).json({ error: 'Reason required' });
    await pool.query(
      'INSERT INTO reports (reporter_id, reported_id, reason) VALUES ($1,$2,$3)',
      [req.user.id, id, String(reason).trim().slice(0, 500)]
    );
    console.log('🚩 Report:', req.user.id, '→', id, '|', reason);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- STATUS / STORIES ---------- */
app.post('/api/statuses', auth, async (req, res) => {
  try {
    const { media_url, media_type, caption } = req.body;
    if (!media_url || !media_type) return res.status(400).json({ error: 'Media required' });
    const r = await pool.query(
      'INSERT INTO statuses (user_id, media_url, media_type, caption) VALUES ($1,$2,$3,$4) RETURNING id, media_url, media_type, caption, created_at, expires_at',
      [req.user.id, media_url, media_type, String(caption||'').slice(0,200)]
    );
    // broadcast to all online users so their stories row refreshes
    io.emit('status-added', { userId: req.user.id });
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/feed', auth, async (req, res) => {
  try {
    // active statuses grouped by user
    const r = await pool.query(`
      SELECT s.user_id, u.display_name, u.avatar_color, u.avatar_url,
        COUNT(s.id) AS status_count,
        MAX(s.created_at) AS latest_at,
        BOOL_AND(CASE WHEN sv.viewer_id IS NOT NULL THEN true ELSE false END) AS all_seen
      FROM statuses s
      JOIN users u ON u.id = s.user_id
      LEFT JOIN status_views sv ON sv.status_id = s.id AND sv.viewer_id = $1
      WHERE s.expires_at > NOW() AND s.user_id <> $1
      GROUP BY s.user_id, u.display_name, u.avatar_color, u.avatar_url
      ORDER BY all_seen ASC, latest_at DESC
    `, [req.user.id]);

    // Filter by status visibility pref
    const filtered = [];
    for (const row of r.rows){
      const ok = await canViewField(req.user.id, row.user_id, 'status');
      if (ok) filtered.push(row);
    }

    // my own statuses
    const mine = await pool.query(`
      SELECT id, media_url, media_type, caption, created_at, expires_at
      FROM statuses WHERE user_id = $1 AND expires_at > NOW()
      ORDER BY created_at ASC
    `, [req.user.id]);

    res.json({ others: filtered, mine: mine.rows });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/user/:id', auth, async (req, res) => {
  try {
    const uid = Number(req.params.id);
    const allowed = await canViewField(req.user.id, uid, 'status');
    if (!allowed) return res.json([]);
    const r = await pool.query(`
      SELECT s.id, s.media_url, s.media_type, s.caption, s.created_at,
        EXISTS(SELECT 1 FROM status_views WHERE status_id=s.id AND viewer_id=$1) AS seen
      FROM statuses s
      WHERE s.user_id=$2 AND s.expires_at > NOW()
      ORDER BY s.created_at ASC
    `, [req.user.id, uid]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/statuses/:id/view', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    await pool.query(
      'INSERT INTO status_views (status_id, viewer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [sid, req.user.id]
    );
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/statuses/:id', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    const r = await pool.query('DELETE FROM statuses WHERE id=$1 AND user_id=$2 RETURNING id', [sid, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    io.emit('status-added', { userId: req.user.id });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- status viewers ---------- */
app.get('/api/statuses/:id/viewers', auth, async (req, res) => {
  try {
    const sid = Number(req.params.id);
    // only the owner can see viewers
    const own = await pool.query('SELECT 1 FROM statuses WHERE id=$1 AND user_id=$2', [sid, req.user.id]);
    if (!own.rowCount) return res.status(403).json({ error: 'Not your status' });
    const r = await pool.query(`
      SELECT u.id, u.display_name, u.avatar_color, u.avatar_url, sv.viewed_at
      FROM status_views sv
      JOIN users u ON u.id = sv.viewer_id
      WHERE sv.status_id = $1
      ORDER BY sv.viewed_at DESC
    `, [sid]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/statuses/mine/counts', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT s.id, COUNT(sv.viewer_id) AS viewers
      FROM statuses s
      LEFT JOIN status_views sv ON sv.status_id = s.id
      WHERE s.user_id = $1 AND s.expires_at > NOW()
      GROUP BY s.id
      ORDER BY s.created_at ASC
    `, [req.user.id]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- FEED / POSTS ---------- */
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { body, media_url, media_type, community } = req.body;
    const text = String(body || '').trim();
    if (!text && !media_url) return res.status(400).json({ error: 'Empty post' });
    const r = await pool.query(
      'INSERT INTO posts (user_id, body, media_url, media_type, community) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, media_url, media_type, community, created_at',
      [req.user.id, text, media_url || null, media_type || null, community || null]
    );
    const me = await pool.query('SELECT id, display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    io.emit('feed-new-post', { id: r.rows[0].id });
    res.json({ ...r.rows[0], author: me.rows[0] });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/feed', auth, async (req, res) => {
  try {
    const tab = req.query.tab || 'foryou';
    const uid = req.user.id;
    const me = (await pool.query('SELECT interests, joined_communities, follows FROM users WHERE id=$1', [uid])).rows[0] || {};
    const interests = me.interests || [];
    const communities = me.joined_communities || [];

    let orderClause = 'p.created_at DESC';
    if (tab === 'foryou'){
      // algorithmic: engagement + recency. Interests/communities weight.
      orderClause = '(COUNT(DISTINCT pl.user_id) * 2 + COUNT(DISTINCT CASE WHEN pv.vote=1 THEN pv.user_id END) * 3) DESC, p.created_at DESC';
    }

    const r = await pool.query(`
      SELECT p.id, p.body, p.media_url, p.media_type, p.community, p.created_at, p.user_id,
        u.display_name, u.avatar_color, u.avatar_url,
        (SELECT COUNT(*) FROM post_likes WHERE post_id=p.id) AS like_count,
        (SELECT COUNT(*) FROM post_votes WHERE post_id=p.id AND vote=1) AS upvotes,
        (SELECT COUNT(*) FROM post_votes WHERE post_id=p.id AND vote=-1) AS downvotes,
        (SELECT COUNT(*) FROM post_comments WHERE post_id=p.id) AS comment_count,
        EXISTS(SELECT 1 FROM post_likes WHERE post_id=p.id AND user_id=$1) AS liked,
        EXISTS(SELECT 1 FROM post_saves WHERE post_id=p.id AND user_id=$1) AS saved,
        (SELECT vote FROM post_votes WHERE post_id=p.id AND user_id=$1) AS my_vote
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN post_likes pl ON pl.post_id = p.id
      LEFT JOIN post_votes pv ON pv.post_id = p.id
      WHERE p.deleted_at IS NULL
      GROUP BY p.id, u.display_name, u.avatar_color, u.avatar_url
      ORDER BY ${orderClause}
      LIMIT 60
    `, [uid]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    if (r.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
    await pool.query('UPDATE posts SET deleted_at=NOW() WHERE id=$1', [id]);
    io.emit('feed-delete-post', { id });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const has = await pool.query('SELECT 1 FROM post_likes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (has.rowCount){
      await pool.query('DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1,$2)', [id, req.user.id]);
    }
    const c = await pool.query('SELECT COUNT(*) FROM post_likes WHERE post_id=$1', [id]);
    io.emit('feed-post-update', { id, like_count: Number(c.rows[0].count) });
    res.json({ liked: !has.rowCount, like_count: Number(c.rows[0].count) });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/vote', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const vote = Number(req.body.vote);
    if (![1,-1].includes(vote)) return res.status(400).json({ error: 'vote must be 1 or -1' });
    const cur = await pool.query('SELECT vote FROM post_votes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (cur.rowCount && cur.rows[0].vote === vote){
      await pool.query('DELETE FROM post_votes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else if (cur.rowCount){
      await pool.query('UPDATE post_votes SET vote=$1 WHERE post_id=$2 AND user_id=$3', [vote, id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_votes (post_id, user_id, vote) VALUES ($1,$2,$3)', [id, req.user.id, vote]);
    }
    const c = await pool.query(
      'SELECT COUNT(*) FILTER (WHERE vote=1) AS up, COUNT(*) FILTER (WHERE vote=-1) AS down FROM post_votes WHERE post_id=$1', [id]);
    res.json({ my_vote: (cur.rowCount && cur.rows[0].vote === vote) ? 0 : vote, up: Number(c.rows[0].up), down: Number(c.rows[0].down) });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/save', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const has = await pool.query('SELECT 1 FROM post_saves WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    if (has.rowCount){
      await pool.query('DELETE FROM post_saves WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
    } else {
      await pool.query('INSERT INTO post_saves (post_id, user_id) VALUES ($1,$2)', [id, req.user.id]);
    }
    res.json({ saved: !has.rowCount });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query(`
      SELECT c.id, c.body, c.created_at, u.id AS user_id, u.display_name, u.avatar_color, u.avatar_url
      FROM post_comments c
      JOIN users u ON u.id = c.user_id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
      LIMIT 200
    `, [id]);
    res.json(r.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'Empty comment' });
    const r = await pool.query(
      'INSERT INTO post_comments (post_id, user_id, body) VALUES ($1,$2,$3) RETURNING id, body, created_at',
      [id, req.user.id, body.slice(0, 500)]
    );
    const me = await pool.query('SELECT display_name, avatar_color, avatar_url FROM users WHERE id=$1', [req.user.id]);
    const full = { ...r.rows[0], user_id: req.user.id, ...me.rows[0] };
    io.emit('feed-new-comment', { post_id: id, comment: full });
    res.json(full);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- APP LOCK / CHAT LOCK ---------- */
app.post('/api/lock/set-pin', auth, async (req, res) => {
  try {
    const { pin, password } = req.body;
    if (!/^\d{4}$/.test(String(pin||''))) return res.status(400).json({ error: 'PIN must be 4 digits' });
    const me = await pool.query('SELECT pin_hash, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    // If a PIN already exists, require the current password to change it
    if (u.pin_hash) {
      const ok = password ? await bcrypt.compare(String(password), u.password_hash) : false;
      if (!ok) return res.status(401).json({ error: 'Enter your account password to change the PIN' });
    }
    const hash = await bcrypt.hash(String(pin), 10);
    await pool.query('UPDATE users SET pin_hash=$1, app_lock_enabled=true, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/verify-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const me = await pool.query('SELECT pin_hash, pin_attempts, pin_lockout_until FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    if (!u.pin_hash) return res.status(400).json({ error: 'PIN not set' });
    if (u.pin_lockout_until && new Date(u.pin_lockout_until) > new Date()){
      const secs = Math.ceil((new Date(u.pin_lockout_until) - new Date()) / 1000);
      return res.status(429).json({ error: 'Too many attempts. Wait ' + secs + 's' });
    }
    const ok = await bcrypt.compare(String(pin||''), u.pin_hash);
    if (!ok){
      const attempts = (u.pin_attempts || 0) + 1;
      let lockout = null;
      if (attempts >= 5) lockout = new Date(Date.now() + 5 * 60 * 1000); // 5 min
      await pool.query('UPDATE users SET pin_attempts=$1, pin_lockout_until=$2 WHERE id=$3', [attempts, lockout, req.user.id]);
      return res.status(401).json({ error: 'Incorrect PIN', attempts, remaining: Math.max(0, 5 - attempts) });
    }
    await pool.query('UPDATE users SET pin_attempts=0, pin_lockout_until=NULL WHERE id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/reset-pin', auth, async (req, res) => {
  try {
    const { code, password, new_pin } = req.body;
    if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'New PIN must be 4 digits' });
    const me = await pool.query('SELECT totp_secret, totp_enabled, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    let ok = false;
    // 1) Try 2FA code first (if user has 2FA)
    if (u.totp_enabled && u.totp_secret && code){
      try { ok = speakeasy.totp.verify({ secret: u.totp_secret, encoding:'base32', token: String(code).trim(), window: 1 }); } catch(_){}
    }
    // 2) Fall back to password
    if (!ok && password){
      ok = await bcrypt.compare(String(password), u.password_hash);
    }
    if (!ok) return res.status(401).json({ error: 'Invalid 2FA code or password' });
    const hash = await bcrypt.hash(String(new_pin), 10);
    await pool.query('UPDATE users SET pin_hash=$1, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/lock/status', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT pin_hash, app_lock_enabled, app_lock_timeout_min, chat_lock_enabled, locked_chats, totp_enabled FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    res.json({
      pin_set: !!u.pin_hash,
      app_lock_enabled: !!u.app_lock_enabled,
      app_lock_timeout_min: u.app_lock_timeout_min || 0,
      chat_lock_enabled: !!u.chat_lock_enabled,
      locked_chats: Array.isArray(u.locked_chats) ? u.locked_chats : [],
      totp_enabled: !!u.totp_enabled
    });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/lock/settings', auth, async (req, res) => {
  try {
    const { app_lock_enabled, app_lock_timeout_min, chat_lock_enabled } = req.body;
    const sets=[], vals=[]; let i=1;
    if (app_lock_enabled !== undefined) { sets.push('app_lock_enabled=$' + (i++)); vals.push(!!app_lock_enabled); }
    if (app_lock_timeout_min !== undefined) { sets.push('app_lock_timeout_min=$' + (i++)); vals.push(Number(app_lock_timeout_min) || 0); }
    if (chat_lock_enabled !== undefined) { sets.push('chat_lock_enabled=$' + (i++)); vals.push(!!chat_lock_enabled); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(req.user.id);
    const r = await pool.query('UPDATE users SET ' + sets.join(', ') + ' WHERE id=$' + i + ' RETURNING pin_hash, app_lock_enabled, app_lock_timeout_min, chat_lock_enabled, locked_chats', vals);
    const u = r.rows[0];
    res.json({
      pin_set: !!u.pin_hash,
      app_lock_enabled: !!u.app_lock_enabled,
      app_lock_timeout_min: u.app_lock_timeout_min || 0,
      chat_lock_enabled: !!u.chat_lock_enabled,
      locked_chats: Array.isArray(u.locked_chats) ? u.locked_chats : []
    });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/lock', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const r = await pool.query('SELECT locked_chats FROM users WHERE id=$1', [req.user.id]);
    let list = Array.isArray(r.rows[0].locked_chats) ? r.rows[0].locked_chats.map(Number) : [];
    const has = list.includes(chatId);
    const next = has ? list.filter(function(x){ return x !== chatId; }) : list.concat([chatId]);
    await pool.query('UPDATE users SET locked_chats=$1::jsonb, chat_lock_enabled=$2 WHERE id=$3', [JSON.stringify(next), next.length > 0, req.user.id]);
    res.json({ locked: !has, locked_chats: next });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- WEBAUTHN BIOMETRIC ---------- */
const RP_NAME = 'GistApp';
function getRpId(req){
  try {
    const origin = req.headers.origin || req.headers.referer || '';
    const u = new URL(origin);
    return u.hostname;
  } catch(_){ return 'localhost'; }
}
function getOrigin(req){
  return req.headers.origin || ('http://' + getRpId(req));
}

app.post('/api/webauthn/register-start', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT id, email, display_name, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    const existing = Array.isArray(u.webauthn_credentials) ? u.webauthn_credentials : [];
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: getRpId(req),
      userID: Buffer.from(String(u.id)),
      userName: u.email,
      userDisplayName: u.display_name || u.email,
      attestationType: 'none',
      excludeCredentials: existing.map(function(c){ return { id: c.credentialID }; }),
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'preferred',
        residentKey: 'discouraged'
      }
    });
    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, req.user.id]);
    res.json(options);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/webauthn/register-finish', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_challenge, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const expectedChallenge = me.rows[0].webauthn_challenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge' });
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      requireUserVerification: false
    });
    if (!verification.verified) return res.status(400).json({ error: 'Verification failed' });
    const info = verification.registrationInfo;
    const cred = {
      credentialID: info.credentialID || info.credential?.id,
      credentialPublicKey: Buffer.from(info.credentialPublicKey || info.credential?.publicKey).toString('base64'),
      counter: info.counter || info.credential?.counter || 0,
      createdAt: new Date().toISOString()
    };
    let list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    list.push(cred);
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb, webauthn_challenge=NULL WHERE id=$2', [JSON.stringify(list), req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/webauthn/auth-start', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    if (!list.length) return res.status(400).json({ error: 'No biometric enrolled' });
    const options = await generateAuthenticationOptions({
      rpID: getRpId(req),
      allowCredentials: list.map(function(c){ return { id: c.credentialID }; }),
      userVerification: 'preferred'
    });
    await pool.query('UPDATE users SET webauthn_challenge=$1 WHERE id=$2', [options.challenge, req.user.id]);
    res.json(options);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/webauthn/auth-finish', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT webauthn_challenge, webauthn_credentials FROM users WHERE id=$1', [req.user.id]);
    const expectedChallenge = me.rows[0].webauthn_challenge;
    const list = Array.isArray(me.rows[0].webauthn_credentials) ? me.rows[0].webauthn_credentials : [];
    const credentialId = req.body.id;
    const stored = list.find(function(c){ return c.credentialID === credentialId; });
    if (!stored) return res.status(400).json({ error: 'Credential not found' });
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      credential: {
        id: stored.credentialID,
        publicKey: Buffer.from(stored.credentialPublicKey, 'base64'),
        counter: stored.counter || 0
      },
      requireUserVerification: false
    });
    if (!verification.verified) return res.status(401).json({ error: 'Biometric failed' });
    // update counter
    stored.counter = verification.authenticationInfo.newCounter;
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb, webauthn_challenge=NULL WHERE id=$2', [JSON.stringify(list), req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
});

app.post('/api/webauthn/remove', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET webauthn_credentials=$1::jsonb WHERE id=$2', [JSON.stringify([]), req.user.id]);
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- PIN RESET VIA EMAIL ---------- */
function makeNumericCode(len){
  let out = '';
  for (let i=0;i<len;i++) out += Math.floor(Math.random()*10);
  return out;
}

app.post('/api/lock/request-reset', auth, async (req, res) => {
  try {
    const me = await pool.query('SELECT email, display_name, totp_enabled FROM users WHERE id=$1', [req.user.id]);
    if (!me.rowCount) return res.status(400).json({ error: 'No user' });
    const u = me.rows[0];
    const code = makeNumericCode(6);
    const hash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    await pool.query('UPDATE users SET reset_code_hash=$1, reset_code_expires=$2 WHERE id=$3', [hash, expires, req.user.id]);

    const baseUrl = process.env.APP_URL || 'http://localhost:4000';
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + process.env.SMTP_USER + '>',
        to: u.email,
        subject: 'GistApp PIN reset code',
        html: '<div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;padding:28px;background:#f7f5ff;border-radius:20px">' +
          '<h2 style="color:#1c1c22;margin:0 0 12px">Reset your PIN</h2>' +
          '<p style="color:#4a4568;font-size:14px;line-height:1.6">Your 6-digit code is:</p>' +
          '<div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#7b8cff;background:#fff;padding:16px;border-radius:14px;text-align:center;margin:16px 0">' + code + '</div>' +
          '<p style="color:#8e8e93;font-size:12.5px">Code expires in 10 minutes. If you didn\'t request this, ignore this email.</p>' +
          '</div>'
      });
      res.json({ ok: true, sent_to: u.email.replace(/^(..).*(@.*)$/, '$1***$2'), totp_enabled: !!u.totp_enabled });
    } catch(mailErr){
      console.error('Reset code email failed', mailErr.message);
      res.status(500).json({ error: 'Could not send email' });
    }
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/lock/verify-reset', auth, async (req, res) => {
  try {
    const { code, new_pin } = req.body;
    if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'New PIN must be 4 digits' });
    const me = await pool.query('SELECT reset_code_hash, reset_code_expires FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    if (!u.reset_code_hash || !u.reset_code_expires) return res.status(400).json({ error: 'No reset requested' });
    if (new Date(u.reset_code_expires) < new Date()) return res.status(400).json({ error: 'Code expired' });
    const ok = await bcrypt.compare(String(code||''), u.reset_code_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect code' });
    const hash = await bcrypt.hash(String(new_pin), 10);
    await pool.query('UPDATE users SET pin_hash=$1, reset_code_hash=NULL, reset_code_expires=NULL, pin_attempts=0, pin_lockout_until=NULL WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- UNIFIED RESET ACTION ---------- */
app.post('/api/lock/reset-action', auth, async (req, res) => {
  try {
    const { method, code, action, new_pin, new_password } = req.body;
    if (!method || !code || !action) return res.status(400).json({ error: 'Missing fields' });
    const me = await pool.query('SELECT totp_secret, totp_enabled, reset_code_hash, reset_code_expires, password_hash FROM users WHERE id=$1', [req.user.id]);
    const u = me.rows[0];
    let verified = false;

    if (method === 'totp'){
      if (!u.totp_enabled || !u.totp_secret) return res.status(400).json({ error: '2FA not enabled' });
      try { verified = speakeasy.totp.verify({ secret: u.totp_secret, encoding:'base32', token: String(code).trim(), window: 1 }); } catch(_){}
    } else if (method === 'email'){
      if (!u.reset_code_hash || !u.reset_code_expires) return res.status(400).json({ error: 'Request a code first' });
      if (new Date(u.reset_code_expires) < new Date()) return res.status(400).json({ error: 'Code expired' });
      verified = await bcrypt.compare(String(code).trim(), u.reset_code_hash);
    }
    if (!verified) return res.status(401).json({ error: 'Invalid code' });

    if (action === 'set_pin'){
      if (!/^\d{4}$/.test(String(new_pin||''))) return res.status(400).json({ error: 'PIN must be 4 digits' });
      const hash = await bcrypt.hash(String(new_pin), 10);
      await pool.query('UPDATE users SET pin_hash=$1, pin_attempts=0, pin_lockout_until=NULL, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$2', [hash, req.user.id]);
      return res.json({ ok: true, message: 'PIN updated' });
    }
    if (action === 'set_password'){
      if (!new_password || String(new_password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      const hash = await bcrypt.hash(String(new_password), 10);
      await pool.query('UPDATE users SET password_hash=$1, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$2', [hash, req.user.id]);
      return res.json({ ok: true, message: 'Password updated' });
    }
    if (action === 'disable_lock'){
      await pool.query('UPDATE users SET app_lock_enabled=false, pin_hash=NULL, pin_attempts=0, pin_lockout_until=NULL, reset_code_hash=NULL, reset_code_expires=NULL WHERE id=$1', [req.user.id]);
      return res.json({ ok: true, message: 'App lock disabled' });
    }
    res.status(400).json({ error: 'Unknown action' });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= PASSWORD RESET ================= */
app.post('/api/pw-reset/request', async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const r = await pool.query('SELECT id, display_name FROM users WHERE email=$1', [email]);
    if (!r.rowCount) return res.json({ ok: true });
    const u = r.rows[0];
    const token = makeToken();
    const expires = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('UPDATE users SET pw_reset_token=$1, pw_reset_expires=$2 WHERE id=$3', [token, expires, u.id]);
    const baseUrl = process.env.APP_URL || 'http://localhost:4000';
    const link = baseUrl + '/reset-password?token=' + token;
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + process.env.SMTP_USER + '>',
        to: email,
        subject: 'Reset your GistApp password',
        html: '<p>Hi ' + (u.display_name || 'there') + ',</p><p>Reset your password: <a href="' + link + '">' + link + '</a></p><p>Link expires in 30 minutes.</p>'
      });
    } catch(_){}
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/reset-password', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  const r = await pool.query('SELECT id FROM users WHERE pw_reset_token=$1 AND pw_reset_expires > NOW()', [token]);
  if (!r.rowCount) return res.send('<html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#050505;color:#fff"><h2 style="color:#ff453a">Link expired</h2><a href="/" style="color:#7b8cff">Back to app</a></body></html>');
  const safeToken = JSON.stringify(token);
  res.send('<html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>body{font-family:Inter,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}.c{background:#fff;color:#1c1c22;max-width:400px;width:100%;padding:32px 24px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5);box-sizing:border-box}h2{margin:0 0 8px;font-size:22px}p{color:#8e8e96;margin:0 0 20px;font-size:14px}input{width:100%;height:50px;border-radius:14px;border:1.5px solid #e8e5f0;background:#faf9fd;padding:0 16px;font-size:15px;margin-bottom:12px;box-sizing:border-box;outline:none}button{width:100%;height:52px;background:#14141a;color:#fff;border:none;border-radius:16px;font-size:15px;font-weight:700;cursor:pointer}.e{color:#e5484d;font-size:13px;min-height:18px;font-weight:600;margin-bottom:6px}</style></head><body><div class=c><h2>Set a new password</h2><p>Minimum 6 characters.</p><div class=e id=e></div><input id=p1 type=password placeholder="New password"><input id=p2 type=password placeholder="Confirm password"><button onclick="save()">Save password</button></div><script>async function save(){var e=document.getElementById("e");e.textContent="";var p1=document.getElementById("p1").value;var p2=document.getElementById("p2").value;if(p1.length<6){e.textContent="Password must be at least 6 characters";return}if(p1!==p2){e.textContent="Passwords do not match";return}try{const r=await fetch("/api/pw-reset/complete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:' + safeToken + ',password:p1})});const j=await r.json();if(!r.ok)throw new Error(j.error||"Failed");document.body.innerHTML="<div style=font-family:Inter;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:20px><div><div style=font-size:60px>OK</div><h2>Password updated</h2><a href=/ style=color:#7b8cff>Open GistApp</a></div></div>"}catch(err){e.textContent=err.message}}</script></body></html>');
});

app.post('/api/pw-reset/complete', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 6) return res.status(400).json({ error: 'Invalid input' });
    const r = await pool.query('SELECT id FROM users WHERE pw_reset_token=$1 AND pw_reset_expires > NOW()', [token]);
    if (!r.rowCount) return res.status(400).json({ error: 'Token expired or invalid' });
    const hash = await bcrypt.hash(String(password), 10);
    await pool.query('UPDATE users SET password_hash=$1, pw_reset_token=NULL, pw_reset_expires=NULL WHERE id=$2', [hash, r.rows[0].id]);
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= GROUP ADMIN ================= */
app.post('/api/chats/:id/members/add', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins can add members' });
    const email = String(req.body.email || '').toLowerCase().trim();
    const u = await pool.query('SELECT id, display_name FROM users WHERE email=$1', [email]);
    if (!u.rowCount) return res.status(404).json({ error: 'No user with that email' });
    const uid = u.rows[0].id;
    const existing = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, uid]);
    if (existing.rowCount) return res.status(409).json({ error: 'Already a member' });
    await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending')", [chatId, uid]);
    io.to('user:' + uid).emit('requests-changed');
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/remove', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins can remove' });
    const uid = Number(req.body.user_id);
    if (uid === req.user.id) return res.status(400).json({ error: 'Use Leave group instead' });
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, uid]);
    io.to('user:' + uid).emit('chats-changed');
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/promote', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    await pool.query('UPDATE chat_members SET is_admin=true WHERE chat_id=$1 AND user_id=$2', [chatId, Number(req.body.user_id)]);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/members/demote', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    await pool.query('UPDATE chat_members SET is_admin=false WHERE chat_id=$1 AND user_id=$2', [chatId, Number(req.body.user_id)]);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/chats/:id/members', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const ok = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!ok.rowCount) return res.status(403).json({ error: 'Not a member' });
    const r = await pool.query("SELECT u.id, u.display_name, u.email, u.avatar_color, u.avatar_url, m.is_admin, m.status FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=$1 ORDER BY m.is_admin DESC, u.display_name ASC", [chatId]);
    res.json(r.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/leave', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
    const others = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1', [chatId]);
    others.rows.forEach(function(row){ io.to('user:' + row.user_id).emit('chats-changed'); });
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/chats/:id/info', auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);
    const me = await pool.query("SELECT is_admin FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
    if (!me.rowCount || !me.rows[0].is_admin) return res.status(403).json({ error: 'Only admins' });
    const { name, description, icon_emoji } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (name !== undefined){ sets.push('name=$' + (i++)); vals.push(String(name).trim().slice(0, 80)); }
    if (description !== undefined){ sets.push('description=$' + (i++)); vals.push(String(description).slice(0, 500)); }
    if (icon_emoji !== undefined){ sets.push('icon_emoji=$' + (i++)); vals.push(String(icon_emoji).slice(0, 8)); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(chatId);
    await pool.query('UPDATE chats SET ' + sets.join(', ') + ' WHERE id=$' + i, vals);
    io.to('chat:' + chatId).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= GLOBAL MESSAGE SEARCH ================= */
app.get('/api/search/messages', auth, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (!q || q.length < 2) return res.json([]);
    const r = await pool.query("SELECT m.id, m.chat_id, m.body, m.created_at, m.media_url, m.media_type, u.display_name AS sender_name, u.avatar_color AS sender_color, u.avatar_url AS sender_url, c.type AS chat_type, c.name AS chat_name FROM messages m JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=$1 AND cm.status='accepted' JOIN users u ON u.id=m.sender_id JOIN chats c ON c.id=m.chat_id WHERE m.deleted_at IS NULL AND LOWER(m.body) LIKE $2 ORDER BY m.created_at DESC LIMIT 80", [req.user.id, '%' + q.toLowerCase() + '%']);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= EDIT POST ================= */
app.patch('/api/posts/:id', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const p = await pool.query('SELECT user_id FROM posts WHERE id=$1', [id]);
    if (!p.rowCount) return res.status(404).json({ error: 'Not found' });
    if (p.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
    const body = String(req.body.body || '').trim().slice(0, 1000);
    await pool.query('UPDATE posts SET body=$1, edited_at=NOW() WHERE id=$2', [body, id]);
    io.emit('feed-update-post', { id: id, body: body });
    res.json({ ok: true, body: body });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ================= SHARE / REPOST ================= */
app.post('/api/posts/:id/share', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const orig = await pool.query('SELECT body, media_url, media_type, user_id FROM posts WHERE id=$1', [id]);
    if (!orig.rowCount) return res.status(404).json({ error: 'Not found' });
    await pool.query('INSERT INTO post_shares (post_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    const caption = String(req.body.caption || '').trim().slice(0, 500);
    const r = await pool.query('INSERT INTO posts (user_id, body, original_post_id) VALUES ($1,$2,$3) RETURNING id, created_at', [req.user.id, caption, id]);
    io.emit('feed-new-post', { id: r.rows[0].id });
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ================= FOLLOW / FOLLOWERS ================= */
app.post('/api/users/:id/follow', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });
    const has = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
    if (has.rowCount){
      await pool.query('DELETE FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
      res.json({ following: false });
    } else {
      await pool.query('INSERT INTO user_follows (follower_id, following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, id]);
      res.json({ following: true });
    }
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id/stats', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const followers = await pool.query('SELECT COUNT(*) FROM user_follows WHERE following_id=$1', [id]);
    const following = await pool.query('SELECT COUNT(*) FROM user_follows WHERE follower_id=$1', [id]);
    const posts = await pool.query('SELECT COUNT(*) FROM posts WHERE user_id=$1 AND deleted_at IS NULL', [id]);
    const isFollowing = await pool.query('SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, id]);
    res.json({
      followers: Number(followers.rows[0].count),
      following: Number(following.rows[0].count),
      posts: Number(posts.rows[0].count),
      is_following: isFollowing.rowCount > 0
    });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- /verify (email verification link) ---------- */
app.get('/verify', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).send('<h2>Missing token</h2>');
  try {
    const r = await pool.query('SELECT id, email, display_name FROM users WHERE verify_token=$1 AND verify_expires > NOW()', [token]);
    if (!r.rowCount) {
      return res.send('<html><body style="font-family:Inter,system-ui,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px"><div style="background:#fff;color:#1c1c22;max-width:400px;padding:40px 30px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5)"><div style="font-size:56px;margin-bottom:10px">\u26A0\uFE0F</div><h2 style="margin:0 0 10px;color:#e5484d">Link expired</h2><p style="color:#8e8e96;font-size:14px;line-height:1.5">This verification link is invalid or has already been used.</p><a href="/" style="color:#7b8cff;font-weight:700;margin-top:20px;display:inline-block">Back to app</a></div></body></html>');
    }
    await pool.query('UPDATE users SET verified=true, verify_token=NULL, verify_expires=NULL WHERE id=$1', [r.rows[0].id]);
    res.send('<html><body style="font-family:Inter,system-ui,sans-serif;background:#050505;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px"><div style="background:#fff;color:#1c1c22;max-width:400px;padding:40px 30px;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.5)"><div style="font-size:56px;margin-bottom:10px">\u2705</div><h2 style="margin:0 0 10px">Email verified!</h2><p style="color:#8e8e96;font-size:14px;line-height:1.5">Welcome, ' + (r.rows[0].display_name || '') + '. Your account is now active.</p><a href="/" style="display:inline-block;margin-top:20px;background:#33344c;color:#fff;text-decoration:none;padding:13px 28px;border-radius:14px;font-weight:700">Open GistApp</a></div></body></html>');
  } catch(e){ console.error(e); res.status(500).send('<h2>Verification failed</h2>'); }
});

/* ---------- BLOCKS LIST ---------- */
app.get('/api/blocks', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT blocked_ids FROM users WHERE id=$1', [req.user.id]);
    const ids = (r.rows[0].blocked_ids || []).map(Number);
    if (!ids.length) return res.json([]);
    const u = await pool.query('SELECT id, display_name, email, avatar_color, avatar_url FROM users WHERE id = ANY($1)', [ids]);
    res.json(u.rows);
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});


/* ---------- WHATSAPP-STYLE CHAT ACTIONS ---------- */
app.post('/api/chats/:id/pin', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT pinned FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!r.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !r.rows[0].pinned;
    // Limit 3 pins
    if (next){
      const c = await pool.query('SELECT COUNT(*) FROM chat_members WHERE user_id=$1 AND pinned=true', [req.user.id]);
      if (Number(c.rows[0].count) >= 3) return res.status(400).json({ error: 'Max 3 pinned chats' });
    }
    await pool.query('UPDATE chat_members SET pinned=$1 WHERE chat_id=$2 AND user_id=$3', [next, id, req.user.id]);
    res.json({ pinned: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/unread', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await pool.query('SELECT unread FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!r.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !r.rows[0].unread;
    await pool.query('UPDATE chat_members SET unread=$1 WHERE chat_id=$2 AND user_id=$3', [next, id, req.user.id]);
    res.json({ unread: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/chats/:id/mute', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { duration } = req.body; // '8h' | '1w' | 'always' | 'off'
    let until = null;
    if (duration === '8h') until = new Date(Date.now() + 8*3600*1000);
    else if (duration === '1w') until = new Date(Date.now() + 7*24*3600*1000);
    else if (duration === 'always') until = new Date('2100-01-01');
    else until = null;
    await pool.query('UPDATE chat_members SET muted=$1, mute_until=$2 WHERE chat_id=$3 AND user_id=$4',
      [!!until, until, id, req.user.id]);
    res.json({ muted: !!until, mute_until: until });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/chats/:id/messages', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    await pool.query('DELETE FROM messages WHERE chat_id=$1', [id]);
    io.to('chat:' + id).emit('chats-changed');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

/* ---------- STAR / PIN MESSAGES ---------- */
app.patch('/api/messages/:id/star', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const m = await pool.query('SELECT chat_id, starred_by FROM messages WHERE id=$1', [id]);
    if (!m.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [m.rows[0].chat_id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const list = Array.isArray(m.rows[0].starred_by) ? m.rows[0].starred_by : [];
    const has = list.indexOf(req.user.id) !== -1;
    const next = has ? list.filter(function(x){ return x !== req.user.id; }) : list.concat([req.user.id]);
    await pool.query('UPDATE messages SET starred_by=$1 WHERE id=$2', [JSON.stringify(next), id]);
    res.json({ starred: !has });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/messages/:id/pin', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const m = await pool.query('SELECT chat_id, pinned FROM messages WHERE id=$1', [id]);
    if (!m.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [m.rows[0].chat_id, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
    const next = !m.rows[0].pinned;
    await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2', [next, id]);
    io.to('chat:' + m.rows[0].chat_id).emit('message-pinned', { id: id, pinned: next });
    res.json({ pinned: next });
  } catch(e){ res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/messages/:id/forward', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { to_chat } = req.body;
    const src = await pool.query('SELECT body, media_url, media_type FROM messages WHERE id=$1', [id]);
    if (!src.rowCount) return res.status(404).json({ error: 'Not found' });
    const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [to_chat, req.user.id]);
    if (!mem.rowCount) return res.status(403).json({ error: 'Not a member of target' });
    const r = await pool.query(
      'INSERT INTO messages (chat_id, sender_id, body, media_url, media_type) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, created_at, sender_id, media_url, media_type',
      [to_chat, req.user.id, src.rows[0].body, src.rows[0].media_url, src.rows[0].media_type]
    );
    const u = await pool.query('SELECT display_name, avatar_color FROM users WHERE id=$1', [req.user.id]);
    const full = Object.assign({}, r.rows[0], { display_name: u.rows[0].display_name, avatar_color: u.rows[0].avatar_color, chat_id: to_chat });
    io.to('chat:' + to_chat).emit('message', full);
    res.json(full);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- Custom notifications + media visibility on chat_members ---------- */
app.patch('/api/chats/:id/prefs', auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { custom_notif, media_visible } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (custom_notif !== undefined){ sets.push('custom_notif=$' + (i++)); vals.push(!!custom_notif); }
    if (media_visible !== undefined){ sets.push('media_visible=$' + (i++)); vals.push(!!media_visible); }
    if (!sets.length) return res.json({ ok: true });
    vals.push(id); vals.push(req.user.id);
    await pool.query('UPDATE chat_members SET ' + sets.join(', ') + ' WHERE chat_id=$' + i + ' AND user_id=$' + (i+1), vals);
    res.json({ ok: true });
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});


/* ---------- USER PROFILE with visibility enforcement ---------- */
app.get('/api/users/:id/profile', auth, async (req, res) => {
  try {
    const uid = Number(req.params.id);
    const r = await pool.query('SELECT id, display_name, username, email, avatar_color, avatar_url, cover_url, bio, last_seen_at, prefs FROM users WHERE id=$1', [uid]);
    if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
    const u = r.rows[0];
    const out = {
      id: u.id,
      display_name: u.display_name,
      username: u.username,
      avatar_color: u.avatar_color
    };
    // Avatar
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'profile_photo')) out.avatar_url = u.avatar_url;
    // Cover
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'profile_photo')) out.cover_url = u.cover_url;
    // Bio / About
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'about')) out.bio = u.bio;
    // Email — only to self
    if (Number(req.user.id) === uid) out.email = u.email;
    // Last seen
    if (Number(req.user.id) === uid || await canViewField(req.user.id, uid, 'last_seen')) out.last_seen_at = u.last_seen_at;

    res.json(out);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- socket ---------- */
io.use((socket,next)=>{
  const token = socket.handshake.auth&&socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token,JWT_SECRET); next(); }
  catch { next(new Error('Bad token')); }
});
io.on('connection', socket=>{
  const uid = Number(socket.user.id);
  socket.join('user:'+uid);
  onlineUsers.set(uid,(onlineUsers.get(uid)||0)+1);
  io.emit('presence',{userId:uid,online:true});
  socket.emit('presence-list',[...onlineUsers.keys()]);
  socket.on('join',chatId=>socket.join('chat:'+chatId));
  socket.on('leave',chatId=>socket.leave('chat:'+chatId));
  socket.on('typing',({chatId,typing})=>socket.to('chat:'+chatId).emit('typing',{userId:uid,typing}));
    /* ========== CALL SIGNALING ========== */
  socket.on('call:initiate', ({ to, kind }) => {
    const callId = 'call_' + uid + '_' + to + '_' + Date.now();
    io.to('user:' + to).emit('call:incoming', { callId, from: uid, kind });
    socket.emit('call:initiated', { callId, to: Number(to), kind });
    console.log('📞 call initiated', callId, kind, uid, '->', to);
  });

  socket.on('call:accept', ({ callId }) => {
    socket.emit('call:accepted', { callId });
    socket.broadcast.emit('call:accepted', { callId });
    console.log('✅ call accepted', callId);
  });

  socket.on('call:reject', ({ callId, reason }) => {
    socket.broadcast.emit('call:rejected', { callId, reason: reason || 'declined' });
    console.log('❌ call rejected', callId);
  });

  socket.on('call:end', ({ callId }) => {
    socket.broadcast.emit('call:ended', { callId });
    console.log('🔚 call ended', callId);
  });

  socket.on('call:signal', ({ callId, to, payload }) => {
    io.to('user:' + to).emit('call:signal', { callId, from: uid, payload });
  });

socket.on('disconnect', async ()=>{
    const n = (onlineUsers.get(uid)||1)-1;
    if (n<=0){
      onlineUsers.delete(uid);
      io.emit('presence',{userId:uid,online:false});
      try { await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1',[uid]); } catch(_){}
    } else onlineUsers.set(uid,n);
  });
});


async function purgeExpired(){
  try {
    const r = await pool.query('DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < NOW() RETURNING id, chat_id');
    r.rows.forEach(row => io.to('chat:' + row.chat_id).emit('message-deleted', { id: row.id }));
    if (r.rowCount) console.log('🧹 Purged ' + r.rowCount + ' expired message(s)');
  } catch(e){
    // Neon sometimes drops idle connections — silently skip this tick
    if (!String(e.message).includes('timeout') && !String(e.message).includes('terminated')){
      console.error('purge error', e.message);
    }
  }
}
setInterval(purgeExpired, 60 * 1000); // every minute
setInterval(async () => {
  try {
    const r = await pool.query('DELETE FROM statuses WHERE expires_at < NOW() RETURNING id');
    if (r.rowCount) console.log('🧹 Purged ' + r.rowCount + ' expired status(es)');
  } catch(e){ console.error('status purge', e.message); }
}, 5 * 60 * 1000); // every 5 min

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log(`Server running → http://localhost:${PORT}`));
