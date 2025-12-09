const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // <-- AGREGAR ESTO
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ==================== CORS PARA RAILWAY ====================
// Configuración específica para Railway
const corsOptions = {
  origin: function (origin, callback) {
    // Permitir estos orígenes 
    const allowedOrigins = [
      'https://comforting-strudel-cb2b2f.netlify.app',
      'http://localhost:8080',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    
    // Permitir requests sin origen (como curl)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('Origen bloqueado:', origin);
      callback(new Error('CORS no permitido para este origen'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Usa el middleware de cors
app.use(cors(corsOptions));

// Manejo explícito de OPTIONS para Railway
app.options('*', cors(corsOptions));

app.use(express.json());

// ==================== CONEXIÓN A MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI;

console.log('='.repeat(50));
console.log('🔧 INICIANDO SERVIDOR GPS TRACKER');
console.log('='.repeat(50));
console.log('🔍 Variables de entorno:');
console.log('   NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('   PORT:', process.env.PORT || 3000);
console.log('   MONGODB_URI:', MONGODB_URI ? 'PRESENTE' : 'FALTANTE!');
console.log('='.repeat(50));

if (!MONGODB_URI) {
  console.error('❌ ERROR CRÍTICO: MONGODB_URI no está definida');
  process.exit(1);
}

console.log('🔗 Conectando a MongoDB Atlas...');

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  family: 4
})
  .then(() => {
    console.log('✅ Conectado a MongoDB Atlas correctamente!');
    console.log('📊 Base de datos:', mongoose.connection.db?.databaseName);
  })
  .catch(err => {
    console.error('❌ Error CRÍTICO conectando a MongoDB:', err.message);
    process.exit(1);
  });

// Eventos de conexión MongoDB
mongoose.connection.on('error', err => {
  console.error('❌ Error de conexión MongoDB:', err);
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  Desconectado de MongoDB');
});

// ==================== ESQUEMAS ====================

// Esquema para ubicaciones GPS
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  username: { type: String }, // 🆕 Agregar username para fácil referencia
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  accuracy: Number,
  timestamp: { type: Date, default: Date.now }
});

const Location = mongoose.model('Location', locationSchema);

// Esquema para usuarios - CON EMAIL REQUERIDO Y ÚNICO
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  deviceId: { type: String, unique: true, sparse: true }, // 🆕 ID único para dispositivo
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

// Método para comparar contraseñas (simple)
userSchema.methods.comparePassword = function(password) {
  return this.password === password;
};

const User = mongoose.model('User', userSchema);

// ==================== MIDDLEWARE DE AUTENTICACIÓN ====================

const auth = {
  // Verificar token JWT
  verifyToken: (req, res, next) => {
    try {
      // Obtener token del header
      const token = req.headers['authorization']?.replace('Bearer ', '') || 
                   req.headers['x-auth-token'];
      
      if (!token) {
        console.log('❌ No token provided');
        return res.status(401).json({
          success: false,
          error: 'Acceso denegado. Token no proporcionado.'
        });
      }

      // Verificar token
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      req.user = decoded;
      next();
    } catch (error) {
      console.error('❌ Token verification error:', error.message);
      return res.status(401).json({
        success: false,
        error: 'Token inválido o expirado.'
      });
    }
  },

  // Verificar si es admin
  isAdmin: (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({
        success: false,
        error: 'Acceso denegado. Se requieren permisos de administrador.'
      });
    }
  }
};

// ==================== RUTAS PÚBLICAS ====================

// Ruta de prueba
app.get('/', (req, res) => {
  res.json({
    message: '🚀 GPS Tracker API funcionando!',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    status: 'online',
    timestamp: new Date().toISOString(),
    cors: 'Enabled',
    endpoints: {
      public: [
        'POST /api/login',
        'POST /api/register',
        'GET  /api/cors-test'
      ],
      protected: [
        'POST /api/location',
        'GET  /api/locations/:userId',
        'GET  /api/admin/users (admin only)',
        'GET  /api/admin/user/:userId (admin only)'
      ]
    }
  });
});

// Endpoint de prueba CORS - MUY IMPORTANTE PARA DEBUG
app.get('/api/cors-test', (req, res) => {
  res.json({
    message: '✅ CORS funcionando correctamente',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'No origin header',
    corsHeaders: {
      'Access-Control-Allow-Origin': res.get('Access-Control-Allow-Origin'),
      'Access-Control-Allow-Methods': res.get('Access-Control-Allow-Methods'),
      'Access-Control-Allow-Headers': res.get('Access-Control-Allow-Headers')
    },
    yourIp: req.ip
  });
});

// ==================== AUTENTICACIÓN PÚBLICA ====================

// Registrar usuario
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    
    console.log('📝 Intentando registrar usuario:', { username, email: email || 'no email' });
    console.log('Body completo:', req.body);
    
    // Validaciones básicas
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario y contraseña son requeridos' 
      });
    }
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email es requerido' 
      });
    }
    
    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      return res.status(400).json({ 
        success: false, 
        error: 'Formato de email inválido' 
      });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ 
        success: false, 
        error: 'El usuario debe tener al menos 3 caracteres' 
      });
    }
    
    if (password.length < 4) {
      return res.status(400).json({ 
        success: false, 
        error: 'La contraseña debe tener al menos 4 caracteres' 
      });
    }
    
    // Verificar si usuario existe
    const existingUsername = await User.findOne({ username: username.trim() });
    if (existingUsername) {
      return res.status(400).json({ 
        success: false, 
        error: 'El nombre de usuario ya está registrado' 
      });
    }
    
    // Verificar si email existe
    const existingEmail = await User.findOne({ email: email.trim().toLowerCase() });
    if (existingEmail) {
      return res.status(400).json({ 
        success: false, 
        error: 'El email ya está registrado' 
      });
    }
    
    // Generar deviceId único
    const deviceId = `device_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    
    // Crear usuario
    const user = new User({
      username: username.trim(),
      email: email.trim().toLowerCase(),
      password: password,
      role: role || 'user',
      deviceId: deviceId
    });
    
    await user.save();
    
    console.log('✅ Usuario registrado exitosamente:', username);
    
    // Generar token JWT
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        username: user.username, 
        role: user.role,
        deviceId: user.deviceId 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Usuario registrado exitosamente',
      user: { 
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        deviceId: user.deviceId
      },
      token: token
    });
    
  } catch (error) {
    console.error('❌ Error registrando usuario:', error);
    
    if (error.code === 11000) {
      // Determinar qué campo causó el error de duplicado
      if (error.keyPattern?.email) {
        return res.status(400).json({ 
          success: false, 
          error: 'El email ya está registrado' 
        });
      }
      if (error.keyPattern?.username) {
        return res.status(400).json({ 
          success: false, 
          error: 'El nombre de usuario ya está registrado' 
        });
      }
      if (error.keyPattern?.deviceId) {
        return res.status(400).json({ 
          success: false, 
          error: 'Error interno: ID duplicado, intenta de nuevo' 
        });
      }
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('🔑 Intentando login para:', username);
    console.log('Login body:', req.body);
    
    // Validaciones básicas
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario y contraseña son requeridos' 
      });
    }
    
    // Buscar usuario por username o email
    let user = await User.findOne({ username: username.trim() });
    if (!user) {
      // Intentar buscar por email
      user = await User.findOne({ email: username.trim().toLowerCase() });
    }
    
    if (!user) {
      console.log('❌ Usuario no encontrado:', username);
      return res.status(401).json({ 
        success: false, 
        error: 'Usuario o contraseña incorrectos' 
      });
    }
    
    // Verificar contraseña
    if (user.password !== password.trim()) {
      console.log('❌ Contraseña incorrecta para:', username);
      return res.status(401).json({ 
        success: false, 
        error: 'Usuario o contraseña incorrectos' 
      });
    }
    
    // Actualizar último login
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });
    
    console.log('✅ Login exitoso:', username, 'Rol:', user.role);
    
    // Generar token JWT
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        username: user.username, 
        role: user.role,
        deviceId: user.deviceId 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        deviceId: user.deviceId
      },
      token: token
    });
    
  } catch (error) {
    console.error('❌ Error en login:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor' 
    });
  }
});

// Endpoint para debug - listar usuarios (solo para desarrollo)
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json({
      count: users.length,
      users: users.map(u => ({
        id: u._id,
        username: u.username,
        email: u.email,
        role: u.role,
        deviceId: u.deviceId,
        createdAt: u.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verificar si usuario existe
app.get('/api/users/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    
    let user;
    if (identifier.includes('@')) {
      user = await User.findOne({ email: identifier.trim().toLowerCase() });
    } else {
      user = await User.findOne({ username: identifier.trim() });
    }
    
    res.json({
      exists: !!user,
      username: user?.username || null,
      email: user?.email || null,
      role: user?.role || null
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ==================== RUTAS PROTEGIDAS ====================

// Guardar ubicación (protegida pero también acepta sin auth para compatibilidad)
app.post('/api/location', async (req, res) => {
  try {
    // Intentar obtener userId del token o del body
    let userId;
    let username = '';
    
    // Verificar si hay token
    const token = req.headers['authorization']?.replace('Bearer ', '') || 
                 req.headers['x-auth-token'];
    
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        userId = decoded.deviceId || decoded.id;
        username = decoded.username || '';
      } catch (tokenError) {
        console.log('⚠️ Token inválido, usando userId del body');
      }
    }
    
    // Si no hay token válido, usar userId del body
    if (!userId) {
      userId = req.body.userId;
    }
    
    const { latitude, longitude, accuracy } = req.body;

    console.log('📍 Recibiendo ubicación para guardar:', { 
      userId, 
      username,
      latitude, 
      longitude,
      source: token ? 'authenticated' : 'anonymous'
    });

    // Validaciones básicas
    if (!userId || latitude === undefined || longitude === undefined) {
      return res.status(400).json({ 
        success: false, 
        error: 'Datos incompletos: userId, latitude y longitude son requeridos' 
      });
    }

    // Si no tenemos username pero tenemos userId, buscar usuario
    if (!username) {
      try {
        const user = await User.findOne({ 
          $or: [
            { deviceId: userId },
            { _id: userId },
            { username: userId }
          ]
        });
        if (user) {
          username = user.username;
        }
      } catch (err) {
        console.log('⚠️ No se pudo obtener username:', err.message);
      }
    }

    let location;

    // Guardar en BD
    if (mongoose.connection.readyState === 1) {
      location = new Location({
        userId: userId.toString(),
        username: username,
        latitude,
        longitude,
        accuracy: accuracy || 0
      });

      await location.save();
      console.log('💾 Ubicación GUARDADA en BD para usuario:', username || userId);
    }

    // EMITIR por WebSocket
    io.emit('locationUpdate', {
      userId,
      username: username,
      latitude,
      longitude,
      accuracy: accuracy || 0,
      timestamp: location?.timestamp || new Date()
    });

    io.to('admin-room').emit('adminLocationUpdate', {
      userId,
      username: username,
      latitude,
      longitude,
      accuracy: accuracy || 0,
      timestamp: location?.timestamp || new Date(),
      type: 'user_update'
    });

    res.json({
      success: true,
      message: 'Ubicación procesada correctamente',
      saved: !!location,
      user: {
        id: userId,
        username: username
      }
    });

  } catch (error) {
    console.error('❌ Error procesando ubicación:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor',
      details: error.message
    });
  }
});

// Obtener ubicaciones de un usuario
app.get('/api/locations/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    const limit = parseInt(req.query.limit) || 50;
    const locations = await Location.find({ userId })
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json(locations);

  } catch (error) {
    console.error('Error obteniendo ubicaciones:', error);
    res.json([]);
  }
});

// ==================== RUTAS DE ADMINISTRACIÓN ====================

// Obtener TODOS los usuarios (PARA ADMIN)
app.get('/api/admin/users', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    // Primero obtener todos los usuarios de la colección User
    const users = await User.find({}, 'username email role deviceId createdAt lastLogin');
    
    // Obtener información de ubicaciones para cada usuario
    const usersWithLocations = await Promise.all(
      users.map(async (user) => {
        const lastLocation = await Location.findOne({ userId: user.deviceId || user._id.toString() })
          .sort({ timestamp: -1 })
          .limit(1);
        
        const locationCount = await Location.countDocuments({ userId: user.deviceId || user._id.toString() });
        
        return {
          userId: user.deviceId || user._id.toString(),
          username: user.username,
          email: user.email || 'Sin email',
          role: user.role,
          createdAt: user.createdAt,
          lastLogin: user.lastLogin,
          lastLocation: lastLocation ? {
            latitude: lastLocation.latitude,
            longitude: lastLocation.longitude,
            accuracy: lastLocation.accuracy,
            timestamp: lastLocation.timestamp
          } : null,
          locationCount: locationCount,
          lastSeen: lastLocation?.timestamp || user.lastLogin || user.createdAt,
          firstSeen: user.createdAt,
          status: lastLocation && (new Date() - new Date(lastLocation.timestamp) < 300000) ? 'online' : 'offline'
        };
      })
    );

    // Ordenar por última actividad
    usersWithLocations.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));

    console.log(`📊 Enviando ${usersWithLocations.length} usuarios al admin`);
    res.json(usersWithLocations);

  } catch (error) {
    console.error('Error obteniendo usuarios admin:', error);
    res.json([]);
  }
});

// Obtener historial completo de un usuario (PARA ADMIN)
app.get('/api/admin/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 500;

    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    // Buscar ubicaciones por userId (deviceId) o _id
    const locations = await Location.find({ userId })
      .sort({ timestamp: 1 })
      .limit(limit);

    console.log(`📊 Enviando ${locations.length} ubicaciones para usuario: ${userId}`);
    res.json(locations);

  } catch (error) {
    console.error('Error obteniendo historial de usuario:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ==================== SOCKET.IO CONFIGURACIÓN ====================

// CORS para Socket.IO - MÁS PERMISIVO
const io = socketIo(server, {
  cors: {
    origin: "*", // Permitir todos los orígenes
    methods: ["GET", "POST"],
    credentials: true,
    transports: ['websocket', 'polling']
  },
  allowEIO3: true
});

// ==================== WEBSOCKETS ====================

io.on('connection', (socket) => {
  console.log('🔌 Cliente conectado:', socket.id, 'Desde:', socket.handshake.headers.origin);

  // Registrar usuario por WebSocket
  socket.on("register-user", async (data) => {
    if (!data || !data.userId) return;

    socket.userId = data.userId.toString();

    try {
      // Buscar información del usuario
      const user = await User.findOne({ 
        $or: [
          { deviceId: socket.userId },
          { _id: socket.userId }
        ]
      });
      
      const username = user ? user.username : socket.userId;

      console.log("🟢 Usuario registrado por WebSocket:", username);

      // Avisar a los admins
      io.to("admin-room").emit("adminLocationUpdate", {
        userId: socket.userId,
        username: username,
        type: "user_connected",
        timestamp: new Date()
      });
    } catch (err) {
      console.log("🟢 Usuario anónimo conectado:", socket.userId);
      io.to("admin-room").emit("adminLocationUpdate", {
        userId: socket.userId,
        username: socket.userId,
        type: "user_connected",
        timestamp: new Date()
      });
    }
  });

  socket.on("send-location", async (loc) => {
    if (!loc || !loc.userId) return;

    console.log("📍 Ubicación recibida por WebSocket de:", loc.userId);

    try {
      // Buscar información del usuario
      const user = await User.findOne({ 
        $or: [
          { deviceId: loc.userId },
          { _id: loc.userId }
        ]
      });
      
      const username = user ? user.username : loc.userId;

      // Guardar en la base de datos
      const location = new Location({
        userId: loc.userId,
        username: username,
        latitude: loc.latitude,
        longitude: loc.longitude,
        accuracy: loc.accuracy || 0
      });

      await location.save();
      console.log('💾 Ubicación WebSocket guardada para:', username);

      // Reenviar a los admins con nombre de usuario
      io.to("admin-room").emit("adminLocationUpdate", {
        ...loc,
        username: username,
        type: "user_update",
        timestamp: new Date()
      });

      // Broadcast general
      io.emit("locationUpdate", {
        ...loc,
        username: username,
        timestamp: new Date()
      });

    } catch (err) {
      console.error('Error procesando ubicación WebSocket:', err);
      // Enviar igual aunque falle la BD
      io.to("admin-room").emit("adminLocationUpdate", {
        ...loc,
        username: loc.userId,
        type: "user_update",
        timestamp: new Date()
      });
    }
  });

  // Admin se une a la sala
  socket.on('join-admin-room', () => {
    socket.join('admin-room');
    console.log('👨‍💼 Admin conectado:', socket.id);
  });

  socket.on('disconnect', () => {
    console.log('🔌 Cliente desconectado:', socket.id);

    if (socket.userId) {
      io.to("admin-room").emit("adminLocationUpdate", {
        userId: socket.userId,
        type: "user_disconnected",
        timestamp: new Date()
      });
    }
  });
});

// ==================== MANEJO DE ERRORES GLOBAL ====================

// Manejo de errores 404
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    error: 'Ruta no encontrada',
    path: req.url,
    method: req.method
  });
});

// Manejo de errores generales
app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== INICIAR SERVIDOR ====================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(50));
  console.log('🚀 GPS TRACKER BACKEND INICIADO');
  console.log('='.repeat(50));
  console.log(`📍 Servidor: http://localhost:${PORT}`);
  console.log(`🌍 CORS: Habilitado para todos los orígenes`);
  console.log(`🔗 WebSocket: ws://localhost:${PORT}`);
  console.log(`🗄️  Base de datos: MongoDB Atlas`);
  console.log(`🔐 JWT: Activado`);
  console.log('='.repeat(50));
  console.log('📋 Endpoints disponibles:');
  console.log('  POST /api/login');
  console.log('  POST /api/register');
  console.log('  POST /api/location');
  console.log('  GET  /api/admin/users');
  console.log('  GET  /api/admin/user/:userId');
  console.log('  GET  /api/debug/users (para testing)');
  console.log('='.repeat(50));
});

// Manejo de señales para shutdown limpio
process.on('SIGINT', () => {
  console.log('\n🛑 Recibida señal SIGINT. Cerrando servidor...');
  mongoose.connection.close();
  server.close(() => {
    console.log('✅ Servidor cerrado correctamente');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Recibida señal SIGTERM. Cerrando servidor...');
  mongoose.connection.close();
  server.close(() => {
    console.log('✅ Servidor cerrado correctamente');
    process.exit(0);
  });
});