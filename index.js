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
const nodemailer   = require('nodemailer');
const speakeasy    = require('speakeasy');
const qrcode       = require('qrcode');

/* ---------- mailer (Gmail SMTP) ---------- */
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
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
    subject: 'Verify your GistApp account',
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
    let emailSent = false, emailError = null;
    try {
      await sendVerificationEmail(email.toLowerCase(), vtoken, name);
      emailSent = true;
      console.log('✅ Verification email sent to', email.toLowerCase());
    } catch(mailErr){
      emailError = mailErr.message;
      console.error('❌ Email send failed:', mailErr.message);
    }
    res.json({
      user: r.rows[0],
      token: sign(r.rows[0]),
      needsVerification: true,
      emailSent,
      emailError
    });
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
  const r = await pool.query('SELECT id,email,display_name,avatar_color,dark_mode,font_size,blocked_ids,prefs,avatar_url,cover_url,bio,totp_enabled FROM users WHERE id=$1',[req.user.id]);
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

  // Enforce avatar visibility
  const rows = await Promise.all(r.rows.map(async c => {
    if (c.other_id && c.other_url){
      const ok = await canViewPhoto(req.user.id, c.other_id);
      if (!ok) c.other_url = null;
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
    try {
      await mailer.sendMail({
        from: '"GistApp" <' + process.env.SMTP_USER + '>',
        to: target,
        subject: 'Confirm your new GistApp email',
        html: '<p>Tap the link below to confirm this email address for your GistApp account:</p>' +
              '<p><a href="' + link + '">' + link + '</a></p>' +
              '<p>Link expires in 24 hours.</p>'
      });
    } catch(mailErr){ console.error('Email send failed:', mailErr.message); }
    res.json({ ok: true, sent_to: target });
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
    try {
      await sendVerificationEmail(email, token, r.rows[0].display_name);
      res.json({ ok: true });
    } catch(e){ console.error('resend failed', e.message); res.status(500).json({ error: 'Could not send email: ' + e.message }); }
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
  } catch(e){ console.error('purge error', e.message); }
}
setInterval(purgeExpired, 60 * 1000); // every minute

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log(`Server running → http://localhost:${PORT}`));
