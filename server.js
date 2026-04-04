const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

const JWT_SECRET = process.env.JWT_SECRET || 'sesli-platform-secret-key-2024';
const PORT = process.env.PORT || 3000;
const DB_FILE = './db.json';

// ─── SADE JSON VERİTABANI (native modül yok, derleme gerektirmez) ────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: [], rooms: [], messages: [], counters: { users: 0, rooms: 0, messages: 0 } };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], rooms: [], messages: [], counters: { users: 0, rooms: 0, messages: 0 } }; }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const db = {
  addUser(user) {
    const data = loadDB();
    data.counters.users++;
    user.id = data.counters.users;
    user.created_at = new Date().toISOString();
    user.status = 'offline';
    data.users.push(user);
    saveDB(data);
    return user;
  },
  updateUser(id, fields) {
    const data = loadDB();
    const i = data.users.findIndex(u => u.id === id);
    if (i !== -1) { Object.assign(data.users[i], fields); saveDB(data); }
  },
  findUser(predicate) { return loadDB().users.find(predicate); },
  addRoom(room) {
    const data = loadDB();
    data.counters.rooms++;
    room.id = data.counters.rooms;
    room.created_at = new Date().toISOString();
    data.rooms.push(room);
    saveDB(data);
    return room;
  },
  findRoom(id) { return loadDB().rooms.find(r => r.id === id); },
  deleteRoom(id) {
    const data = loadDB();
    data.rooms = data.rooms.filter(r => r.id !== id);
    data.messages = data.messages.filter(m => m.room_id !== id);
    saveDB(data);
  },
  getAllRooms() {
    const data = loadDB();
    return data.rooms.map(room => {
      const owner = data.users.find(u => u.id === room.owner_id);
      return { ...room, owner_name: owner ? owner.username : 'Bilinmiyor', member_count: 0 };
    }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  },
  addMessage(msg) {
    const data = loadDB();
    data.counters.messages++;
    msg.id = data.counters.messages;
    msg.created_at = new Date().toISOString();
    data.messages.push(msg);
    if (data.messages.length > 500) data.messages = data.messages.slice(-500);
    saveDB(data);
    return msg;
  },
  getRoomMessages(roomId) {
    const data = loadDB();
    return data.messages
      .filter(m => m.room_id === roomId)
      .slice(-50)
      .map(m => {
        const user = data.users.find(u => u.id === m.user_id);
        return { ...m, username: user ? user.username : 'Bilinmiyor' };
      });
  }
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH ─────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  if (username.length < 3)
    return res.status(400).json({ error: 'Kullanıcı adı en az 3 karakter olmalı' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
  const existing = db.findUser(u => u.username === username || u.email === email);
  if (existing)
    return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = db.addUser({ username, email, password: hashed });
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username, email } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-posta ve şifre zorunlu' });
  try {
    const user = db.findUser(u => u.email === email || u.username === email);
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Şifre yanlış' });
    db.updateUser(user.id, { status: 'online' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Geçersiz token' }); }
}

// ─── ROOMS ────────────────────────────────────────────────────
app.get('/api/rooms', (req, res) => {
  const rooms = db.getAllRooms().map(r => ({
    ...r,
    password: r.password ? true : false,
    member_count: Object.keys(roomParticipants[r.id] || {}).length
  }));
  res.json(rooms);
});

app.post('/api/rooms', authMiddleware, (req, res) => {
  const { name, description, is_private, password, max_users, category } = req.body;
  if (!name) return res.status(400).json({ error: 'Oda adı zorunlu' });
  try {
    const hashedPw = password ? bcrypt.hashSync(password, 10) : null;
    const room = db.addRoom({
      name, description: description || '', owner_id: req.user.id,
      is_private: is_private ? 1 : 0, password: hashedPw,
      max_users: max_users || 50, category: category || 'genel'
    });
    res.json({ id: room.id, name, message: 'Oda oluşturuldu' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Oda oluşturulamadı' }); }
});

app.delete('/api/rooms/:id', authMiddleware, (req, res) => {
  const roomId = parseInt(req.params.id);
  const room = db.findRoom(roomId);
  if (!room) return res.status(404).json({ error: 'Oda bulunamadı' });
  if (room.owner_id !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
  db.deleteRoom(roomId);
  io.to('room:' + roomId).emit('room:deleted');
  res.json({ message: 'Oda silindi' });
});

app.get('/api/rooms/:id/messages', (req, res) => {
  res.json(db.getRoomMessages(parseInt(req.params.id)));
});

// ─── SOCKET.IO ────────────────────────────────────────────────
const roomParticipants = {};
function getRoomUsers(roomId) { return Object.values(roomParticipants[roomId] || {}); }

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token gerekli'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Geçersiz token')); }
});

io.on('connection', (socket) => {
  console.log('✅ ' + socket.user.username + ' bağlandı (' + socket.id + ')');
  db.updateUser(socket.user.id, { status: 'online' });
  io.emit('user:status', { userId: socket.user.id, status: 'online' });

  socket.on('room:join', (data) => {
    const { roomId, password } = data;
    const room = db.findRoom(parseInt(roomId));
    if (!room) return socket.emit('error', { message: 'Oda bulunamadı' });
    if (room.password) {
      if (!password) return socket.emit('room:password_required');
      if (!bcrypt.compareSync(password, room.password))
        return socket.emit('error', { message: 'Oda şifresi yanlış' });
    }
    const currentCount = Object.keys(roomParticipants[roomId] || {}).length;
    if (currentCount >= room.max_users) return socket.emit('error', { message: 'Oda dolu' });
    if (socket.currentRoom) {
      socket.leave('room:' + socket.currentRoom);
      if (roomParticipants[socket.currentRoom]) {
        delete roomParticipants[socket.currentRoom][socket.id];
        io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
      }
    }
    socket.join('room:' + roomId);
    socket.currentRoom = roomId;
    if (!roomParticipants[roomId]) roomParticipants[roomId] = {};
    roomParticipants[roomId][socket.id] = {
      userId: socket.user.id, username: socket.user.username,
      socketId: socket.id, muted: false, deafened: false,
      isSharingScreen: false // Ekran Paylaşımı Durumu
    };
    socket.emit('room:joined', { roomId, users: getRoomUsers(roomId) });
    socket.to('room:' + roomId).emit('room:user_joined', {
      userId: socket.user.id, username: socket.user.username, socketId: socket.id
    });
    io.to('room:' + roomId).emit('room:users', getRoomUsers(roomId));
    console.log('🎙️ ' + socket.user.username + ' → oda ' + roomId);
  });

  socket.on('room:leave', () => leaveCurrentRoom(socket));

  // Ses verisi: istemciden gelir, odadaki herkese iletilir
  socket.on('voice:data', ({ roomId, chunk, sampleRate }) => {
    if (!chunk || !roomId) return;
    if (!socket.currentRoom || socket.currentRoom != roomId) return;
    // Göndereni hariç odadaki herkese ilet
    socket.to('room:' + roomId).emit('voice:data', {
      fromUserId: socket.user.id,
      fromUsername: socket.user.username,
      chunk,
      sampleRate
    });
  });

  socket.on('message:send', ({ roomId, content }) => {
    if (!content || !roomId || content.length > 500) return;
    try {
      const msg = db.addMessage({ room_id: parseInt(roomId), user_id: socket.user.id, content });
      io.to('room:' + roomId).emit('message:new', {
        id: msg.id, username: socket.user.username,
        userId: socket.user.id, content, created_at: msg.created_at
      });
    } catch (e) { console.error(e); }
  });

  // Ekran Paylaşımı Sinyali
  socket.on('webrtc:signal', (data) => {
    io.to(data.to).emit('webrtc:signal', { from: socket.id, signal: data.signal, type: data.type });
  });

  socket.on('user:screen_share_toggle', (isSharing) => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom] || !roomParticipants[socket.currentRoom][socket.id]) return;
    roomParticipants[socket.currentRoom][socket.id].isSharingScreen = isSharing;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
    socket.to('room:' + socket.currentRoom).emit('user:screen_share_status', { socketId: socket.id, isSharing });
  });

  socket.on('user:mute_toggle', () => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom] || !roomParticipants[socket.currentRoom][socket.id]) return;
    const u = roomParticipants[socket.currentRoom][socket.id];
    u.muted = !u.muted;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  // Bas Konuş için net mikrofon durumu ataması
  socket.on('user:set_mute', (isMuted) => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom] || !roomParticipants[socket.currentRoom][socket.id]) return;
    const u = roomParticipants[socket.currentRoom][socket.id];
    u.muted = isMuted;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  socket.on('user:deafen_toggle', () => {
    if (!socket.currentRoom || !roomParticipants[socket.currentRoom] || !roomParticipants[socket.currentRoom][socket.id]) return;
    const u = roomParticipants[socket.currentRoom][socket.id];
    u.deafened = !u.deafened;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  socket.on('disconnect', () => {
    console.log('❌ ' + socket.user.username + ' ayrıldı');
    leaveCurrentRoom(socket);
    db.updateUser(socket.user.id, { status: 'offline' });
    io.emit('user:status', { userId: socket.user.id, status: 'offline' });
  });

  function leaveCurrentRoom(socket) {
    const roomId = socket.currentRoom;
    if (!roomId) return;
    socket.leave('room:' + roomId);
    if (roomParticipants[roomId]) {
      delete roomParticipants[roomId][socket.id];
      io.to('room:' + roomId).emit('room:user_left', {
        userId: socket.user.id, username: socket.user.username, socketId: socket.id
      });
      io.to('room:' + roomId).emit('room:users', getRoomUsers(roomId));
      if (Object.keys(roomParticipants[roomId]).length === 0) delete roomParticipants[roomId];
    }
    socket.currentRoom = null;
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log('🚀 Sunucu: http://localhost:' + PORT);
});
