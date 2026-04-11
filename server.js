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
  addUser(u) { const d=loadDB(); d.counters.users++; u.id=d.counters.users; u.created_at=new Date().toISOString(); u.status='offline'; d.users.push(u); saveDB(d); return u; },
  updateUser(id, f) { const d=loadDB(); const i=d.users.findIndex(u=>u.id===id); if(i!==-1){Object.assign(d.users[i],f);saveDB(d);} },
  findUser(fn) { return loadDB().users.find(fn); },
  addRoom(r) { const d=loadDB(); d.counters.rooms++; r.id=d.counters.rooms; r.created_at=new Date().toISOString(); d.rooms.push(r); saveDB(d); return r; },
  findRoom(id) { return loadDB().rooms.find(r=>r.id===id); },
  deleteRoom(id) { const d=loadDB(); d.rooms=d.rooms.filter(r=>r.id!==id); d.messages=d.messages.filter(m=>m.room_id!==id); saveDB(d); },
  getAllRooms() {
    const d=loadDB();
    return d.rooms.map(r=>{ const o=d.users.find(u=>u.id===r.owner_id); return {...r,owner_name:o?o.username:'?',member_count:0}; })
      .sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
  },
  addMessage(m) { const d=loadDB(); d.counters.messages++; m.id=d.counters.messages; m.created_at=new Date().toISOString(); d.messages.push(m); if(d.messages.length>500)d.messages=d.messages.slice(-500); saveDB(d); return m; },
  getRoomMessages(rid) { const d=loadDB(); return d.messages.filter(m=>m.room_id===rid).slice(-50).map(m=>{const u=d.users.find(u=>u.id===m.user_id);return{...m,username:u?u.username:'?'};}); }
};

app.use(cors()); app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

app.post('/api/register', async (req,res) => {
  const {username,email,password}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Tüm alanlar zorunlu'});
  if(username.length<3) return res.status(400).json({error:'Kullanıcı adı en az 3 karakter'});
  if(password.length<6) return res.status(400).json({error:'Şifre en az 6 karakter'});
  if(db.findUser(u=>u.username===username||u.email===email)) return res.status(400).json({error:'Kullanıcı adı veya e-posta kullanılıyor'});
  try {
    const hashed=await bcrypt.hash(password,10);
    const user=db.addUser({username,email,password:hashed});
    const token=jwt.sign({id:user.id,username},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:user.id,username,email}});
  } catch { res.status(500).json({error:'Sunucu hatası'}); }
});

app.post('/api/login', async (req,res) => {
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'E-posta ve şifre zorunlu'});
  try {
    const user=db.findUser(u=>u.email===email||u.username===email);
    if(!user) return res.status(400).json({error:'Kullanıcı bulunamadı'});
    if(!await bcrypt.compare(password,user.password)) return res.status(400).json({error:'Şifre yanlış'});
    db.updateUser(user.id,{status:'online'});
    const token=jwt.sign({id:user.id,username:user.username},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:user.id,username:user.username,email:user.email}});
  } catch { res.status(500).json({error:'Sunucu hatası'}); }
});

function auth(req,res,next) {
  const token=req.headers.authorization&&req.headers.authorization.split(' ')[1];
  if(!token) return res.status(401).json({error:'Token gerekli'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch{res.status(401).json({error:'Geçersiz token'});}
}

// roomMembers[roomId][userId] = {...}  — userId ile indexleme, socket değişince atma olmaz
const roomMembers = {};
function getRoomUsers(rid) { return Object.values(roomMembers[rid]||{}); }
function countMembers(rid) { return Object.keys(roomMembers[rid]||{}).length; }
function roomsData() {
  return db.getAllRooms().map(r=>({...r,password:!!r.password,member_count:countMembers(r.id)}));
}
function broadcast() { io.emit('rooms:list',roomsData()); }

app.get('/api/rooms',(req,res)=>res.json(roomsData()));
app.post('/api/rooms',auth,(req,res)=>{
  const{name,description,is_private,password,max_users,category}=req.body;
  if(!name) return res.status(400).json({error:'Oda adı zorunlu'});
  try{
    const hp=password?bcrypt.hashSync(password,10):null;
    const room=db.addRoom({name,description:description||'',owner_id:req.user.id,is_private:is_private?1:0,password:hp,max_users:max_users||50,category:category||'genel'});
    broadcast();
    res.json({id:room.id,name,message:'Oda oluşturuldu'});
  }catch{res.status(500).json({error:'Oda oluşturulamadı'});}
});
app.delete('/api/rooms/:id',auth,(req,res)=>{
  const rid=parseInt(req.params.id);
  const room=db.findRoom(rid);
  if(!room) return res.status(404).json({error:'Oda bulunamadı'});
  if(room.owner_id!==req.user.id) return res.status(403).json({error:'Yetki yok'});
  db.deleteRoom(rid);
  io.to('room:'+rid).emit('room:deleted');
  broadcast();
  res.json({message:'Oda silindi'});
});
app.get('/api/rooms/:id/messages',(req,res)=>res.json(db.getRoomMessages(parseInt(req.params.id))));

// activeSocket[userId] = socketId  — reconnect tespiti için
const activeSocket = {};

io.use((socket,next)=>{
  const token=socket.handshake.auth.token;
  if(!token) return next(new Error('Token gerekli'));
  try{socket.user=jwt.verify(token,JWT_SECRET);next();}
  catch{next(new Error('Geçersiz token'));}
});

io.on('connection',(socket)=>{
  const uid=socket.user.id;
  const uname=socket.user.username;
  console.log('✅ '+uname+' ('+socket.id+')');

  activeSocket[uid]=socket.id;
  db.updateUser(uid,{status:'online'});
  socket.emit('rooms:list',roomsData());

  socket.on('room:join',(data)=>{
    const{roomId,password}=data;
    const rid=parseInt(roomId);
    const room=db.findRoom(rid);
    if(!room) return socket.emit('error',{message:'Oda bulunamadı'});

    if(room.password){
      if(!password) return socket.emit('room:password_required');
      if(!bcrypt.compareSync(password,room.password)) return socket.emit('error',{message:'Oda şifresi yanlış'});
    }

    // Farklı odadaysa önce oradan çık
    if(socket.currentRoom && socket.currentRoom!==rid){
      _leave(socket,socket.currentRoom);
    }

    socket.join('room:'+rid);
    socket.currentRoom=rid;
    if(!roomMembers[rid]) roomMembers[rid]={};

    const zatenVar = uid in roomMembers[rid];

    if(zatenVar){
      // AYNI KULLANICI TEKRAR BAĞLANDI (reconnect/Electron yenileme)
      // Sadece socketId güncelle — kimseye room:user_joined/left GÖNDERİLMEZ
      roomMembers[rid][uid].socketId=socket.id;
      console.log('🔄 '+uname+' reconnect oda:'+rid);
    } else {
      // GERÇEKTEN YENİ KULLANICI
      roomMembers[rid][uid]={userId:uid,username:uname,socketId:socket.id,muted:false,deafened:false,isSharingScreen:false};
      socket.to('room:'+rid).emit('room:user_joined',{userId:uid,username:uname,socketId:socket.id});
      console.log('🎙️ '+uname+' → oda '+rid);
    }

    socket.emit('room:joined',{roomId:rid,users:getRoomUsers(rid)});
    io.to('room:'+rid).emit('room:users',getRoomUsers(rid));
    broadcast();
  });

  socket.on('room:leave',()=>{ _leave(socket,socket.currentRoom); broadcast(); });

  socket.on('voice:data',({roomId,chunk,sampleRate,mimeType})=>{
    if(!chunk||!roomId||!socket.currentRoom||socket.currentRoom!=roomId) return;
    socket.to('room:'+roomId).emit('voice:data',{fromUserId:uid,fromUsername:uname,chunk,sampleRate,mimeType});
  });

  socket.on('message:send',({roomId,content})=>{
    if(!content||!roomId||content.length>500) return;
    try{
      const msg=db.addMessage({room_id:parseInt(roomId),user_id:uid,content});
      io.to('room:'+roomId).emit('message:new',{id:msg.id,username:uname,userId:uid,content,created_at:msg.created_at});
    }catch(e){console.error(e);}
  });

  socket.on('webrtc:signal',(d)=>io.to(d.to).emit('webrtc:signal',{from:socket.id,signal:d.signal,type:d.type}));

  socket.on('user:screen_share_toggle',(isSharing)=>{
    if(!socket.currentRoom||!roomMembers[socket.currentRoom]?.[uid]) return;
    roomMembers[socket.currentRoom][uid].isSharingScreen=isSharing;
    io.to('room:'+socket.currentRoom).emit('room:users',getRoomUsers(socket.currentRoom));
    socket.to('room:'+socket.currentRoom).emit('user:screen_share_status',{socketId:socket.id,isSharing});
  });

  socket.on('user:mute_toggle',()=>{
    if(!socket.currentRoom||!roomMembers[socket.currentRoom]?.[uid]) return;
    roomMembers[socket.currentRoom][uid].muted=!roomMembers[socket.currentRoom][uid].muted;
    io.to('room:'+socket.currentRoom).emit('room:users',getRoomUsers(socket.currentRoom));
  });
  socket.on('user:set_mute',(m)=>{
    if(!socket.currentRoom||!roomMembers[socket.currentRoom]?.[uid]) return;
    roomMembers[socket.currentRoom][uid].muted=m;
    io.to('room:'+socket.currentRoom).emit('room:users',getRoomUsers(socket.currentRoom));
  });
  socket.on('user:deafen_toggle',()=>{
    if(!socket.currentRoom||!roomMembers[socket.currentRoom]?.[uid]) return;
    const u=roomMembers[socket.currentRoom][uid];
    u.deafened=!u.deafened;
    io.to('room:'+socket.currentRoom).emit('room:users',getRoomUsers(socket.currentRoom));
  });

  socket.on('rooms:get',()=>socket.emit('rooms:list',roomsData()));

  socket.on('disconnect',(reason)=>{
    console.log('❌ '+uname+' disconnect:'+reason+' ('+socket.id+')');

    // Bu socket hâlâ aktif değilse (yeni socket bağlandı) hiçbir şey yapma
    if(activeSocket[uid]!==socket.id){
      console.log('ℹ️ '+uname+' eski socket, yoksayıldı');
      return;
    }

    const gecici=['transport error','transport close','ping timeout'].includes(reason);
    if(gecici){
      // Geçici kopma - 12 saniye bekle
      setTimeout(()=>{
        if(activeSocket[uid]===socket.id){
          // Hâlâ geri dönmedi, gerçekten çıkmış
          delete activeSocket[uid];
          db.updateUser(uid,{status:'offline'});
          if(socket.currentRoom){ _leave(socket,socket.currentRoom); broadcast(); }
        }
      },12000);
    } else {
      // Kasıtlı çıkış
      delete activeSocket[uid];
      db.updateUser(uid,{status:'offline'});
      if(socket.currentRoom){ _leave(socket,socket.currentRoom); broadcast(); }
    }
  });

  function _leave(socket,rid){
    if(!rid) return;
    socket.leave('room:'+rid);
    if(roomMembers[rid]&&roomMembers[rid][uid]){
      const sid=roomMembers[rid][uid].socketId;
      delete roomMembers[rid][uid];
      io.to('room:'+rid).emit('room:user_left',{userId:uid,username:uname,socketId:sid});
      io.to('room:'+rid).emit('room:users',getRoomUsers(rid));
      if(Object.keys(roomMembers[rid]).length===0) delete roomMembers[rid];
    }
    socket.currentRoom=null;
  }
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
server.listen(PORT,()=>console.log('🚀 http://localhost:'+PORT));
