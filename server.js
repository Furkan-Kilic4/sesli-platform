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

// ─── VERİTABANI ──────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: [], rooms: [], messages: [], counters: { users: 0, rooms: 0, messages: 0 } };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: [], rooms: [], messages: [], counters: { users: 0, rooms: 0, messages: 0 } }; }
}
function saveDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

const db = {
  addUser(user) {
    const data = loadDB(); data.counters.users++;
    user.id = data.counters.users; user.created_at = new Date().toISOString(); user.status = 'offline';
    data.users.push(user); saveDB(data); return user;
  },
  updateUser(id, fields) {
    const data = loadDB(); const i = data.users.findIndex(u => u.id === id);
    if (i !== -1) { Object.assign(data.users[i], fields); saveDB(data); }
  },
  findUser(predicate) { return loadDB().users.find(predicate); },
  addRoom(room) {
    const data = loadDB(); data.counters.rooms++;
    room.id = data.counters.rooms; room.created_at = new Date().toISOString();
    data.rooms.push(room); saveDB(data); return room;
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
      return { ...room, owner_name: owner ? owner.username : '?', member_count: 0 };
    }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  },
  addMessage(msg) {
    const data = loadDB(); data.counters.messages++;
    msg.id = data.counters.messages; msg.created_at = new Date().toISOString();
    data.messages.push(msg);
    if (data.messages.length > 500) data.messages = data.messages.slice(-500);
    saveDB(data); return msg;
  },
  getRoomMessages(roomId) {
    const data = loadDB();
    return data.messages.filter(m => m.room_id === roomId).slice(-50).map(m => {
      const user = data.users.find(u => u.id === m.user_id);
      return { ...m, username: user ? user.username : '?' };
    });
  }
};

app.use(cors()); app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH ─────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  if (username.length < 3) return res.status(400).json({ error: 'Kullanıcı adı en az 3 karakter' });
  if (password.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter' });
  if (db.findUser(u => u.username === username || u.email === email))
    return res.status(400).json({ error: 'Kullanıcı adı veya e-posta zaten kullanılıyor' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = db.addUser({ username, email, password: hashed });
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username, email } });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-posta ve şifre zorunlu' });
  try {
    const user = db.findUser(u => u.email === email || u.username === email);
    if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Şifre yanlış' });
    db.updateUser(user.id, { status: 'online' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Geçersiz token' }); }
}

// ─── ROOMS API ────────────────────────────────────────
app.get('/api/rooms', (req, res) => {
  const rooms = db.getAllRooms().map(r => ({
    ...r, password: !!r.password,
    member_count: countRoomMembers(r.id)
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
    broadcastRooms();
    res.json({ id: room.id, name, message: 'Oda oluşturuldu' });
  } catch { res.status(500).json({ error: 'Oda oluşturulamadı' }); }
});

app.delete('/api/rooms/:id', authMiddleware, (req, res) => {
  const roomId = parseInt(req.params.id);
  const room = db.findRoom(roomId);
  if (!room) return res.status(404).json({ error: 'Oda bulunamadı' });
  if (room.owner_id !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
  db.deleteRoom(roomId);
  io.to('room:' + roomId).emit('room:deleted');
  broadcastRooms();
  res.json({ message: 'Oda silindi' });
});

app.get('/api/rooms/:id/messages', (req, res) => {
  res.json(db.getRoomMessages(parseInt(req.params.id)));
});

// ─── SOCKET.IO ────────────────────────────────────────

// roomMembers[roomId][userId] = { socketId, username, muted, deafened, isSharingScreen }
// KEY DEĞIŞIKLIK: socketId yerine userId ile indeksleme
// Böylece aynı kullanıcı yeniden bağlandığında "yeni kişi" gibi görünmez
const roomMembers = {};

function getRoomUsers(roomId) {
  return Object.values(roomMembers[roomId] || {});
}

function countRoomMembers(roomId) {
  return Object.keys(roomMembers[roomId] || {}).length;
}

function broadcastRooms() {
  const rooms = db.getAllRooms().map(r => ({
    ...r, password: !!r.password,
    member_count: countRoomMembers(r.id)
  }));
  io.emit('rooms:list', rooms);
}

// userId → aktif socketId (reconnect takibi için)
const activeSocket = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token gerekli'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Geçersiz token')); }
});

io.on('connection', (socket) => {
  const uid = socket.user.id;
  const uname = socket.user.username;
  console.log('✅ ' + uname + ' bağlandı (' + socket.id + ')');

  // Eski socket'i kaydet, yenisini aktifte tut
  activeSocket[uid] = socket.id;
  db.updateUser(uid, { status: 'online' });

  // Bağlanan kullanıcıya oda listesini gönder
  socket.emit('rooms:list', db.getAllRooms().map(r => ({
    ...r, password: !!r.password, member_count: countRoomMembers(r.id)
  })));

  // ── Odaya katıl
  socket.on('room:join', (data) => {
    const { roomId, password, isReconnect } = data;
    const rid = parseInt(roomId);
    const room = db.findRoom(rid);
    if (!room) return socket.emit('error', { message: 'Oda bulunamadı' });

    // Şifre kontrolü
    if (room.password) {
      if (!password) return socket.emit('room:password_required');
      if (!bcrypt.compareSync(password, room.password))
        return socket.emit('error', { message: 'Oda şifresi yanlış' });
    }

    // Kapasite kontrolü (ama aynı kullanıcı zaten içerdeyse sayma)
    const alreadyInRoom = roomMembers[rid] && roomMembers[rid][uid];
    if (!alreadyInRoom) {
      if (countRoomMembers(rid) >= room.max_users)
        return socket.emit('error', { message: 'Oda dolu' });
    }

    // Farklı bir odadaysa önce o odadan çıkar
    if (socket.currentRoom && socket.currentRoom !== rid) {
      _leaveRoom(socket, socket.currentRoom);
    }

    // Socket.IO odasına katıl
    socket.join('room:' + rid);
    socket.currentRoom = rid;

    if (!roomMembers[rid]) roomMembers[rid] = {};

    if (alreadyInRoom) {
      // ── RECONNECT: Aynı kullanıcı aynı odaya tekrar bağlandı
      // Sadece socketId'yi güncelle, kimseye bildirim GÖNDERME
      roomMembers[rid][uid].socketId = socket.id;
      console.log('🔄 ' + uname + ' yeniden bağlandı, oda ' + rid);
    } else {
      // ── YENİ GİRİŞ: Kullanıcı ilk kez bu odaya giriyor
      roomMembers[rid][uid] = {
        userId: uid, username: uname, socketId: socket.id,
        muted: false, deafened: false, isSharingScreen: false
      };
      // Odadakilere "yeni kişi geldi" bildir
      socket.to('room:' + rid).emit('room:user_joined', {
        userId: uid, username: uname, socketId: socket.id
      });
      console.log('🎙️ ' + uname + ' → oda ' + rid);
    }

    // Her iki durumda da kullanıcıya mevcut listeyi gönder
    socket.emit('room:joined', { roomId: rid, users: getRoomUsers(rid) });
    io.to('room:' + rid).emit('room:users', getRoomUsers(rid));
    broadcastRooms();
  });

  // ── Odadan kasıtlı çıkış
  socket.on('room:leave', () => {
    if (socket.currentRoom) {
      _leaveRoom(socket, socket.currentRoom);
      broadcastRooms();
    }
  });

  // ── Ses verisi
  socket.on('voice:data', ({ roomId, chunk, sampleRate, mimeType }) => {
    if (!chunk || !roomId || !socket.currentRoom || socket.currentRoom != roomId) return;
    socket.to('room:' + roomId).emit('voice:data', {
      fromUserId: uid, fromUsername: uname, chunk, sampleRate, mimeType
    });
  });

  // ── Mesaj
  socket.on('message:send', ({ roomId, content }) => {
    if (!content || !roomId || content.length > 500) return;
    try {
      const msg = db.addMessage({ room_id: parseInt(roomId), user_id: uid, content });
      io.to('room:' + roomId).emit('message:new', {
        id: msg.id, username: uname, userId: uid, content, created_at: msg.created_at
      });
    } catch (e) { console.error(e); }
  });

  // ── Ekran paylaşımı
  socket.on('webrtc:signal', (data) => {
    io.to(data.to).emit('webrtc:signal', { from: socket.id, signal: data.signal, type: data.type });
  });
  socket.on('user:screen_share_toggle', (isSharing) => {
    if (!socket.currentRoom || !roomMembers[socket.currentRoom]?.[uid]) return;
    roomMembers[socket.currentRoom][uid].isSharingScreen = isSharing;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
    socket.to('room:' + socket.currentRoom).emit('user:screen_share_status', { socketId: socket.id, isSharing });
  });

  // ── Mute / Deafen
  socket.on('user:mute_toggle', () => {
    if (!socket.currentRoom || !roomMembers[socket.currentRoom]?.[uid]) return;
    const u = roomMembers[socket.currentRoom][uid];
    u.muted = !u.muted;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });
  socket.on('user:set_mute', (isMuted) => {
    if (!socket.currentRoom || !roomMembers[socket.currentRoom]?.[uid]) return;
    roomMembers[socket.currentRoom][uid].muted = isMuted;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });
  socket.on('user:deafen_toggle', () => {
    if (!socket.currentRoom || !roomMembers[socket.currentRoom]?.[uid]) return;
    const u = roomMembers[socket.currentRoom][uid];
    u.deafened = !u.deafened;
    io.to('room:' + socket.currentRoom).emit('room:users', getRoomUsers(socket.currentRoom));
  });

  // ── Oda listesi isteği
  socket.on('rooms:get', () => {
    socket.emit('rooms:list', db.getAllRooms().map(r => ({
      ...r, password: !!r.password, member_count: countRoomMembers(r.id)
    })));
  });

  // ── Bağlantı kesildi
  socket.on('disconnect', (reason) => {
    console.log('❌ ' + uname + ' disconnect: ' + reason + ' (' + socket.id + ')');

    // Bu socket hâlâ aktif socket mi?
    if (activeSocket[uid] !== socket.id) {
      // Değil — yeni bir socket zaten var (reconnect oldu), hiçbir şey yapma
      console.log('ℹ️ ' + uname + ' eski socket disconnect, yeni bağlantı var, yoksayılıyor');
      return;
    }

    // Transport hatası mı? (internet kesilmesi, geçici kopma)
    const isTemporary = ['transport error', 'transport close', 'ping timeout'].includes(reason);

    if (isTemporary) {
      // Geçici kopma — 10 saniye bekle, yeniden bağlanabilir
      setTimeout(() => {
        // Hâlâ bu socket aktif mi?
        if (activeSocket[uid] === socket.id) {
          // 10 saniye geçti, gerçekten gitti
          console.log('⏰ ' + uname + ' 10sn içinde dönmedi, odadan çıkarılıyor');
          delete activeSocket[uid];
          db.updateUser(uid, { status: 'offline' });
          if (socket.currentRoom) {
            _leaveRoom(socket, socket.currentRoom);
            broadcastRooms();
          }
        }
      }, 10000);
    } else {
      // Kasıtlı çıkış (tarayıcı kapandı, logout)
      delete activeSocket[uid];
      db.updateUser(uid, { status: 'offline' });
      if (socket.currentRoom) {
        _leaveRoom(socket, socket.currentRoom);
        broadcastRooms();
      }
    }
  });

  // ── Odadan çıkar (iç fonksiyon)
  function _leaveRoom(socket, roomId) {
    socket.leave('room:' + roomId);
    if (roomMembers[roomId] && roomMembers[roomId][uid]) {
      const memberSocketId = roomMembers[roomId][uid].socketId;
      delete roomMembers[roomId][uid];
      // Odadakilere bildir — socketId olarak son bilinen id'yi kullan
      io.to('room:' + roomId).emit('room:user_left', {
        userId: uid, username: uname, socketId: memberSocketId
      });
      io.to('room:' + roomId).emit('room:users', getRoomUsers(roomId));
      if (Object.keys(roomMembers[roomId]).length === 0) delete roomMembers[roomId];
    }
    socket.currentRoom = null;
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => { console.log('🚀 Sunucu: http://localhost:' + PORT); });
