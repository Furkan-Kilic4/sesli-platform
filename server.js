const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

const JWT_SECRET = process.env.JWT_SECRET || 'sesli-platform-secret-key-2024';
const PORT = process.env.PORT || 3000;

// Veritabanı kur
const db = new Database('./database.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    avatar TEXT DEFAULT NULL,
    status TEXT DEFAULT 'offline',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    owner_id INTEGER NOT NULL,
    is_private INTEGER DEFAULT 0,
    password TEXT DEFAULT NULL,
    max_users INTEGER DEFAULT 50,
    category TEXT DEFAULT 'genel',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(room_id) REFERENCES rooms(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS room_members (
    room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(room_id, user_id)
  );
`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH ROUTES ───────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  if (username.length < 3)
    return res.status(400).json({ error: 'Kullanıcı adı en az 3 karakter olmalı' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(username, email, hashed);
    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: result.lastInsertRowid, username, email } });
  } catch (e) {
    if (e.message.includes('UNIQUE'))
      return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email, email);
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Şifre yanlış' });
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run('online', user.id);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ─── ROOM ROUTES ───────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Geçersiz token' });
  }
}

app.get('/api/rooms', (req, res) => {
  const rooms = db.prepare(`
    SELECT r.*, u.username as owner_name,
    (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.id) as member_count
    FROM rooms r
    JOIN users u ON r.owner_id = u.id
    ORDER BY r.created_at DESC
  `).all();
  res.json(rooms.map(r => ({ ...r, password: r.password ? true : false })));
});

app.post('/api/rooms', authMiddleware, (req, res) => {
  const { name, description, is_private, password, max_users, category } = req.body;
  if (!name) return res.status(400).json({ error: 'Oda adı zorunlu' });
  try {
    const hashedPw = password ? bcrypt.hashSync(password, 10) : null;
    const stmt = db.prepare(
      'INSERT INTO rooms (name, description, owner_id, is_private, password, max_users, category) VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    const result = stmt.run(name, description || '', req.user.id, is_private ? 1 : 0, hashedPw, max_users || 50, category || 'genel');
    res.json({ id: result.lastInsertRowid, name, message: 'Oda oluşturuldu' });
  } catch (e) {
    res.status(500).json({ error: 'Oda oluşturulamadı' });
  }
});

app.delete('/api/rooms/:id', authMiddleware, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(req.params.id);
  if (!room) return res.status(404).json({ error: 'Oda bulunamadı' });
  if (room.owner_id !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
  db.prepare('DELETE FROM rooms WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM room_members WHERE room_id = ?').run(req.params.id);
  io.to(`room:${req.params.id}`).emit('room:deleted');
  res.json({ message: 'Oda silindi' });
});

app.get('/api/rooms/:id/messages', (req, res) => {
  const messages = db.prepare(`
    SELECT m.*, u.username FROM messages m
    JOIN users u ON m.user_id = u.id
    WHERE m.room_id = ?
    ORDER BY m.created_at DESC LIMIT 50
  `).all(req.params.id);
  res.json(messages.reverse());
});

app.get('/api/users/online', (req, res) => {
  const users = db.prepare("SELECT id, username, status FROM users WHERE status = 'online'").all();
  res.json(users);
});

// ─── SOCKET.IO ────────────────────────────────────────────────
// Aktif oda katılımcıları: { roomId: { socketId: { userId, username, muted, deafened } } }
const roomParticipants = {};

function getRoomUsers(roomId) {
  return Object.values(roomParticipants[roomId] || {});
}

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token gerekli'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Geçersiz token'));
  }
});

io.on('connection', (socket) => {
  console.log(`✅ ${socket.user.username} bağlandı (${socket.id})`);

  // Kullanıcı online yap
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('online', socket.user.id);
  io.emit('user:status', { userId: socket.user.id, status: 'online' });

  // ── Odaya katıl
  socket.on('room:join', async (data) => {
    const { roomId, password } = data;
    const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(roomId);
    if (!room) return socket.emit('error', { message: 'Oda bulunamadı' });

    // Şifre kontrolü
    if (room.password) {
      if (!password) return socket.emit('room:password_required');
      const ok = bcrypt.compareSync(password, room.password);
      if (!ok) return socket.emit('error', { message: 'Oda şifresi yanlış' });
    }

    // Kapasite kontrolü
    const currentCount = Object.keys(roomParticipants[roomId] || {}).length;
    if (currentCount >= room.max_users)
      return socket.emit('error', { message: 'Oda dolu' });

    // Önceki odadan çık
    if (socket.currentRoom) {
      socket.leave(`room:${socket.currentRoom}`);
      if (roomParticipants[socket.currentRoom]) {
        delete roomParticipants[socket.currentRoom][socket.id];
        io.to(`room:${socket.currentRoom}`).emit('room:users', getRoomUsers(socket.currentRoom));
      }
    }

    socket.join(`room:${roomId}`);
    socket.currentRoom = roomId;

    if (!roomParticipants[roomId]) roomParticipants[roomId] = {};
    roomParticipants[roomId][socket.id] = {
      userId: socket.user.id,
      username: socket.user.username,
      socketId: socket.id,
      muted: false,
      deafened: false
    };

    // Üyeliği kaydet
    try {
      db.prepare('INSERT OR IGNORE INTO room_members (room_id, user_id) VALUES (?, ?)').run(roomId, socket.user.id);
    } catch {}

    socket.emit('room:joined', { roomId, users: getRoomUsers(roomId) });
    socket.to(`room:${roomId}`).emit('room:user_joined', {
      userId: socket.user.id,
      username: socket.user.username,
      socketId: socket.id
    });
    io.to(`room:${roomId}`).emit('room:users', getRoomUsers(roomId));

    console.log(`🎙️ ${socket.user.username} → oda ${roomId}`);
  });

  // ── Odadan ayrıl
  socket.on('room:leave', () => {
    leaveCurrentRoom(socket);
  });

  // ── WebRTC Signaling
  socket.on('webrtc:offer', ({ targetSocketId, offer }) => {
    io.to(targetSocketId).emit('webrtc:offer', {
      offer,
      fromSocketId: socket.id,
      fromUsername: socket.user.username
    });
  });

  socket.on('webrtc:answer', ({ targetSocketId, answer }) => {
    io.to(targetSocketId).emit('webrtc:answer', {
      answer,
      fromSocketId: socket.id
    });
  });

  socket.on('webrtc:ice_candidate', ({ targetSocketId, candidate }) => {
    io.to(targetSocketId).emit('webrtc:ice_candidate', {
      candidate,
      fromSocketId: socket.id
    });
  });

  // ── Metin mesajı
  socket.on('message:send', ({ roomId, content }) => {
    if (!content || !roomId) return;
    if (content.length > 500) return;
    try {
      const stmt = db.prepare('INSERT INTO messages (room_id, user_id, content) VALUES (?, ?, ?)');
      const result = stmt.run(roomId, socket.user.id, content);
      io.to(`room:${roomId}`).emit('message:new', {
        id: result.lastInsertRowid,
        username: socket.user.username,
        userId: socket.user.id,
        content,
        created_at: new Date().toISOString()
      });
    } catch {}
  });

  // ── Mute/Deafen durumu
  socket.on('user:mute_toggle', () => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom]?.[socket.id]) return;
    const user = roomParticipants[socket.currentRoom][socket.id];
    user.muted = !user.muted;
    io.to(`room:${socket.currentRoom}`).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  socket.on('user:deafen_toggle', () => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom]?.[socket.id]) return;
    const user = roomParticipants[socket.currentRoom][socket.id];
    user.deafened = !user.deafened;
    io.to(`room:${socket.currentRoom}`).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  // ── Bağlantı kesilince
  socket.on('disconnect', () => {
    console.log(`❌ ${socket.user.username} ayrıldı`);
    leaveCurrentRoom(socket);
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run('offline', socket.user.id);
    io.emit('user:status', { userId: socket.user.id, status: 'offline' });
  });

  function leaveCurrentRoom(socket) {
    const roomId = socket.currentRoom;
    if (!roomId) return;
    socket.leave(`room:${roomId}`);
    if (roomParticipants[roomId]) {
      delete roomParticipants[roomId][socket.id];
      io.to(`room:${roomId}`).emit('room:user_left', {
        userId: socket.user.id,
        username: socket.user.username,
        socketId: socket.id
      });
      io.to(`room:${roomId}`).emit('room:users', getRoomUsers(roomId));
      if (Object.keys(roomParticipants[roomId]).length === 0) {
        delete roomParticipants[roomId];
      }
    }
    socket.currentRoom = null;
  }
});

// ─── SERVE FRONTEND ───────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`🚀 Sunucu çalışıyor: http://localhost:${PORT}`);
});
