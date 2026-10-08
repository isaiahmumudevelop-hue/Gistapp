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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const onlineUsers = new Map();

/* ---------- uploads ---------- */
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- auth middleware ---------- */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function sign(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

/* ---------- auth ---------- */
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, display_name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rowCount) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const name = display_name || email.split('@')[0];
    const r = await pool.query(
      'INSERT INTO users (email, password_hash, display_name) VALUES ($1,$2,$3) RETURNING id, email, display_name, avatar_color',
      [email.toLowerCase(), hash, name]
    );
    res.json({ user: r.rows[0], token: sign(r.rows[0]) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    if (!r.rowCount) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({
      user: { id: user.id, email: user.email, display_name: user.display_name, avatar_color: user.avatar_color },
      token: sign(user)
    });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- me ---------- */
app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id, email, display_name, avatar_color, dark_mode FROM users WHERE id=$1', [req.user.id]);
  res.json(r.rows[0]);
});

app.patch('/api/me', auth, async (req, res) => {
  const { display_name, avatar_color, dark_mode } = req.body;
  const sets = []; const vals = []; let i = 1;
  if (display_name !== undefined) { sets.push(`display_name=$${i++}`); vals.push(display_name); }
  if (avatar_color !== undefined) { sets.push(`avatar_color=$${i++}`); vals.push(avatar_color); }
  if (dark_mode !== undefined)    { sets.push(`dark_mode=$${i++}`);    vals.push(!!dark_mode); }
  if (!sets.length) return res.json({ ok: true });
  vals.push(req.user.id);
  const r = await pool.query(
    `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING id, email, display_name, avatar_color, dark_mode`,
    vals
  );
  res.json(r.rows[0]);
});

/* ---------- chats list ---------- */
app.get('/api/chats', auth, async (req, res) => {
  const r = await pool.query(`
    SELECT c.id, c.type, c.name, m.status AS my_status,
      (SELECT body FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE chat_id=c.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_at,
      (SELECT COUNT(*) FROM messages
        WHERE chat_id=c.id AND sender_id<>$1 AND deleted_at IS NULL
        AND created_at > COALESCE(m.last_read_at, '1970-01-01')) AS unread,
      o.id           AS other_id,
      o.display_name AS other_name,
      o.email        AS other_email,
      o.avatar_color AS other_color,
      om.status      AS other_status,
      (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) AS member_count
    FROM chats c
    JOIN chat_members m       ON m.chat_id=c.id AND m.user_id=$1 AND m.status='accepted'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1 AND c.type='dm'
    LEFT JOIN users o         ON o.id=om.user_id
    ORDER BY COALESCE(
      (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1),
      c.created_at
    ) DESC
  `, [req.user.id]);
  res.json(r.rows);
});

/* ---------- requests ---------- */
app.get('/api/requests', auth, async (req, res) => {
  const r = await pool.query(`
    SELECT c.id AS chat_id, c.type, c.name,
      u.id AS user_id, u.display_name, u.email, u.avatar_color, c.created_at
    FROM chats c
    JOIN chat_members m  ON m.chat_id=c.id AND m.user_id=$1 AND m.status='pending'
    LEFT JOIN chat_members om ON om.chat_id=c.id AND om.user_id<>$1
    LEFT JOIN users u    ON u.id=om.user_id
    ORDER BY c.created_at DESC
  `, [req.user.id]);
  res.json(r.rows);
});

app.post('/api/requests/:id/accept', auth, async (req, res) => {
  const chatId = Number(req.params.id);
  const r = await pool.query(
    "UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2 AND status='pending' RETURNING chat_id",
    [chatId, req.user.id]
  );
  if (!r.rowCount) return res.status(404).json({ error: 'No pending request' });
  const others = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2', [chatId, req.user.id]);
  others.rows.forEach(row => io.to('user:' + row.user_id).emit('chats-changed'));
  res.json({ ok: true });
});

app.post('/api/requests/:id/decline', auth, async (req, res) => {
  const chatId = Number(req.params.id);
  const r = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='pending'", [chatId, req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'No pending request' });
  await pool.query('DELETE FROM chats WHERE id=$1', [chatId]);
  res.json({ ok: true });
});

/* ---------- start DM ---------- */
app.post('/api/chats/dm', auth, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const other = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
  if (!other.rowCount) return res.status(404).json({ error: 'User not found' });
  const otherId = other.rows[0].id;
  if (otherId === req.user.id) return res.status(400).json({ error: 'Cannot chat with yourself' });

  const existing = await pool.query(`
    SELECT c.id, a.status AS my_status FROM chats c
    JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
    JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
    WHERE c.type='dm' LIMIT 1
  `, [req.user.id, otherId]);
  if (existing.rowCount) {
    const row = existing.rows[0];
    if (row.my_status === 'pending') {
      await pool.query("UPDATE chat_members SET status='accepted', last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2", [row.id, req.user.id]);
      io.to('user:' + otherId).emit('chats-changed');
    }
    return res.json({ chat_id: row.id });
  }
  const chat = await pool.query("INSERT INTO chats (type) VALUES ('dm') RETURNING id");
  const chatId = chat.rows[0].id;
  await pool.query(
    "INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'accepted'),($1,$3,'pending')",
    [chatId, req.user.id, otherId]
  );
  io.to('user:' + otherId).emit('requests-changed');
  res.json({ chat_id: chatId });
});

/* ---------- create group ---------- */
app.post('/api/chats/group', auth, async (req, res) => {
  const { name, emails } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Group name required' });
  const list = (emails || []).map(e => String(e).trim().toLowerCase()).filter(Boolean);
  if (!list.length) return res.status(400).json({ error: 'Add at least one member' });

  const users = await pool.query('SELECT id, email FROM users WHERE email = ANY($1)', [list]);
  if (users.rowCount !== list.length) {
    const found = users.rows.map(r => r.email);
    const missing = list.filter(e => !found.includes(e));
    return res.status(404).json({ error: 'Not registered: ' + missing.join(', ') });
  }

  const chat = await pool.query("INSERT INTO chats (type,name) VALUES ('group',$1) RETURNING id", [name.trim()]);
  const chatId = chat.rows[0].id;

  await pool.query("INSERT INTO chat_members (chat_id,user_id,status,last_read_at) VALUES ($1,$2,'accepted',NOW())", [chatId, req.user.id]);
  for (const u of users.rows) {
    await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending')", [chatId, u.id]);
    io.to('user:' + u.id).emit('requests-changed');
  }
  res.json({ chat_id: chatId });
});

/* ---------- add member ---------- */
app.post('/api/chats/:id/members', auth, async (req, res) => {
  const chatId = Number(req.params.id);
  const { email } = req.body;
  const mem = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2 AND status='accepted'", [chatId, req.user.id]);
  if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });
  const u = await pool.query('SELECT id FROM users WHERE email=$1', [String(email||'').toLowerCase()]);
  if (!u.rowCount) return res.status(404).json({ error: 'User not found' });
  await pool.query("INSERT INTO chat_members (chat_id,user_id,status) VALUES ($1,$2,'pending') ON CONFLICT DO NOTHING", [chatId, u.rows[0].id]);
  io.to('user:' + u.rows[0].id).emit('requests-changed');
  res.json({ ok: true });
});

/* ---------- messages ---------- */
app.get('/api/chats/:id/messages', auth, async (req, res) => {
  const chatId = req.params.id;
  const q = (req.query.q || '').trim();
  const member = await pool.query('SELECT status FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'Not a member' });
  if (member.rows[0].status !== 'accepted') return res.status(403).json({ error: 'Chat not accepted yet' });

  const params = [chatId];
  let where = 'WHERE m.chat_id=$1';
  if (q) { params.push('%' + q.toLowerCase() + '%'); where += ` AND LOWER(m.body) LIKE $${params.length}`; }

  const r = await pool.query(`
    SELECT m.id, m.body, m.created_at, m.sender_id, m.reactions, m.read_at,
           m.media_url, m.media_type, m.deleted_at,
           u.display_name, u.avatar_color
    FROM messages m JOIN users u ON u.id=m.sender_id
    ${where}
    ORDER BY m.created_at ASC LIMIT 300
  `, params);
  res.json(r.rows);
});

app.post('/api/chats/:id/messages', auth, async (req, res) => {
  const chatId = req.params.id;
  const { body, media_url, media_type } = req.body;
  const text = (body || '').trim();
  if (!text && !media_url) return res.status(400).json({ error: 'Empty message' });
  const member = await pool.query('SELECT status FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'Not a member' });
  if (member.rows[0].status !== 'accepted') return res.status(403).json({ error: 'Chat not accepted yet' });

  let row;
  if (text) {
    const dup = await pool.query(
      "SELECT id, body, created_at, sender_id, reactions, read_at, media_url, media_type FROM messages WHERE chat_id=$1 AND sender_id=$2 AND body=$3 AND deleted_at IS NULL AND created_at > NOW() - INTERVAL '3 seconds' ORDER BY created_at DESC LIMIT 1",
      [chatId, req.user.id, text]
    );
    if (dup.rowCount) row = dup.rows[0];
  }
  if (!row) {
    const r = await pool.query(
      'INSERT INTO messages (chat_id,sender_id,body,media_url,media_type) VALUES ($1,$2,$3,$4,$5) RETURNING id, body, created_at, sender_id, reactions, read_at, media_url, media_type',
      [chatId, req.user.id, text, media_url || null, media_type || null]
    );
    row = r.rows[0];
  }
  const me = await pool.query('SELECT display_name, avatar_color FROM users WHERE id=$1', [req.user.id]);
  const full = { ...row, display_name: me.rows[0].display_name, avatar_color: me.rows[0].avatar_color, chat_id: chatId };
  io.to('chat:' + chatId).emit('message', full);
  res.json(full);
});

/* ---------- react ---------- */
app.patch('/api/messages/:id/react', auth, async (req, res) => {
  const msgId = Number(req.params.id);
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji required' });
  const m = await pool.query('SELECT chat_id, reactions FROM messages WHERE id=$1', [msgId]);
  if (!m.rowCount) return res.status(404).json({ error: 'Message not found' });
  const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [m.rows[0].chat_id, req.user.id]);
  if (!mem.rowCount) return res.status(403).json({ error: 'Not a member' });

  const rx = m.rows[0].reactions || {};
  const arr = Array.isArray(rx[emoji]) ? rx[emoji] : [];
  const uid = req.user.id;
  rx[emoji] = arr.includes(uid) ? arr.filter(x => x !== uid) : [...arr, uid];
  if (!rx[emoji].length) delete rx[emoji];
  await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2', [rx, msgId]);
  io.to('chat:' + m.rows[0].chat_id).emit('reaction', { id: msgId, reactions: rx });
  res.json({ id: msgId, reactions: rx });
});

/* ---------- delete ---------- */
app.delete('/api/messages/:id', auth, async (req, res) => {
  const msgId = Number(req.params.id);
  const m = await pool.query('SELECT chat_id, sender_id FROM messages WHERE id=$1', [msgId]);
  if (!m.rowCount) return res.status(404).json({ error: 'Not found' });
  if (m.rows[0].sender_id !== req.user.id) return res.status(403).json({ error: 'Not yours' });
  await pool.query('UPDATE messages SET deleted_at=NOW(), body=NULL, media_url=NULL WHERE id=$1', [msgId]);
  io.to('chat:' + m.rows[0].chat_id).emit('message-deleted', { id: msgId });
  res.json({ ok: true });
});

/* ---------- read ---------- */
app.post('/api/chats/:id/read', auth, async (req, res) => {
  await pool.query('UPDATE chat_members SET last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  await pool.query('UPDATE messages SET read_at=COALESCE(read_at,NOW()) WHERE chat_id=$1 AND sender_id<>$2', [req.params.id, req.user.id]);
  io.to('chat:' + req.params.id).emit('read', { by: req.user.id });
  res.json({ ok: true });
});

/* ---------- upload ---------- */
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const type = req.file.mimetype.startsWith('image/') ? 'image'
             : req.file.mimetype.startsWith('video/') ? 'video'
             : req.file.mimetype.startsWith('audio/') ? 'audio' : 'file';
  res.json({ url: '/uploads/' + req.file.filename, type });
});

/* ---------- search ---------- */
app.get('/api/search', auth, async (req, res) => {
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
});

/* ---------- socket ---------- */
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Bad token')); }
});

io.on('connection', socket => {
  const uid = Number(socket.user.id);
  socket.join('user:' + uid);
  onlineUsers.set(uid, (onlineUsers.get(uid) || 0) + 1);
  io.emit('presence', { userId: uid, online: true });
  socket.emit('presence-list', [...onlineUsers.keys()]);

  socket.on('join',  chatId => socket.join('chat:' + chatId));
  socket.on('leave', chatId => socket.leave('chat:' + chatId));
  socket.on('typing', ({ chatId, typing }) => {
    socket.to('chat:' + chatId).emit('typing', { userId: uid, socketId: socket.id, typing });
  });
  socket.on('disconnect', () => {
    const n = (onlineUsers.get(uid) || 1) - 1;
    if (n <= 0) { onlineUsers.delete(uid); io.emit('presence', { userId: uid, online: false }); }
    else onlineUsers.set(uid, n);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
