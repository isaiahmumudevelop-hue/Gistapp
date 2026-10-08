require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const pool       = require('./db');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- auth middleware ---------- */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

/* ---------- signup ---------- */
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
    const user  = r.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ user, token });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- login ---------- */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    if (!r.rowCount) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ user: { id: user.id, email: user.email, display_name: user.display_name, avatar_color: user.avatar_color }, token });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

/* ---------- me ---------- */
app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id, email, display_name, avatar_color FROM users WHERE id=$1', [req.user.id]);
  res.json(r.rows[0]);
});

/* ---------- list my chats ---------- */
app.get('/api/chats', auth, async (req, res) => {
  const r = await pool.query(`
    SELECT c.id, c.type, c.name,
      (SELECT body FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_at
    FROM chats c
    JOIN chat_members m ON m.chat_id=c.id
    WHERE m.user_id=$1
    ORDER BY COALESCE(last_at, c.created_at) DESC
  `, [req.user.id]);
  res.json(r.rows);
});

/* ---------- open or create a DM by email ---------- */
app.post('/api/chats/dm', auth, async (req, res) => {
  const { email } = req.body;
  const other = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
  if (!other.rowCount) return res.status(404).json({ error: 'No user with that email' });
  const otherId = other.rows[0].id;
  if (otherId === req.user.id) return res.status(400).json({ error: 'Cannot chat with yourself' });

  const existing = await pool.query(`
    SELECT c.id FROM chats c
    JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
    JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
    WHERE c.type='dm' LIMIT 1
  `, [req.user.id, otherId]);
  if (existing.rowCount) return res.json({ chat_id: existing.rows[0].id });

  const chat = await pool.query("INSERT INTO chats (type) VALUES ('dm') RETURNING id");
  const chatId = chat.rows[0].id;
  await pool.query('INSERT INTO chat_members (chat_id,user_id) VALUES ($1,$2),($1,$3)', [chatId, req.user.id, otherId]);
  res.json({ chat_id: chatId });
});

/* ---------- messages in a chat ---------- */
app.get('/api/chats/:id/messages', auth, async (req, res) => {
  const chatId = req.params.id;
  const member = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'Not a member' });
  const r = await pool.query(`
    SELECT m.id, m.body, m.created_at, m.sender_id, u.display_name, u.avatar_color
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.chat_id=$1 ORDER BY m.created_at ASC LIMIT 200
  `, [chatId]);
  res.json(r.rows);
});

/* ---------- send message ---------- */
app.post('/api/chats/:id/messages', auth, async (req, res) => {
  const chatId = req.params.id;
  const { body } = req.body;
  if (!body || !body.trim()) return res.status(400).json({ error: 'Empty message' });
  const member = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'Not a member' });
  const r = await pool.query(
    'INSERT INTO messages (chat_id,sender_id,body) VALUES ($1,$2,$3) RETURNING id, body, created_at, sender_id',
    [chatId, req.user.id, body.trim()]
  );
  const me = await pool.query('SELECT display_name, avatar_color FROM users WHERE id=$1', [req.user.id]);
  const full = { ...r.rows[0], display_name: me.rows[0].display_name, avatar_color: me.rows[0].avatar_color, chat_id: chatId };
  io.to('chat:' + chatId).emit('message', full);
  res.json(full);
});

/* ---------- socket.io ---------- */
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Bad token')); }
});

io.on('connection', socket => {
  console.log('socket connected:', socket.user.email);
  socket.on('join',  chatId => socket.join('chat:' + chatId));
  socket.on('leave', chatId => socket.leave('chat:' + chatId));
  socket.on('typing', ({ chatId, typing }) => {
    socket.to('chat:' + chatId).emit('typing', { userId: socket.user.id, typing });
  });
  socket.on('disconnect', () => console.log('socket disconnected:', socket.user.email));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
