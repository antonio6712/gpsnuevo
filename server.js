const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ==================== SOCKET.IO ====================
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// ==================== CORS CONFIGURACIÓN ====================
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://comforting-strudel-cb2b2f.netlify.app',
      'http://localhost:8080',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'https://gpsbackend-production.up.railway.app'
    ];
    
    if (!origin) {
      return callback(null, true);
    }
    
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('⚠️ Origen bloqueado:', origin);
      callback(null, true);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// MIDDLEWARE para logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url} - Origin: ${req.headers.origin || 'No origin'}`);
  next();
});

// ==================== CONEXIÓN A MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI || '';

console.log('='.repeat(60));
console.log('🚀 INICIANDO GPS TRACKER API - RAILWAY');
console.log('='.repeat(60));
console.log('🔍 Variables de entorno:');
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
console.log(`   PORT: ${process.env.PORT || 3000}`);
console.log(`   MONGODB_URI: ${MONGODB_URI ? '✓ PRESENTE' : '✗ FALTANTE!'}`);
console.log('='.repeat(60));

if (!MONGODB_URI) {
  console.error('❌ ERROR: MONGODB_URI no está definida');
  console.log('⚠️ Continuando sin conexión a MongoDB...');
} else {
  console.log('🔗 Conectando a MongoDB Atlas...');
  
  let mongoUri = MONGODB_URI;
  if (!mongoUri.includes('/?') && !mongoUri.includes('/gps_')) {
    mongoUri = mongoUri.replace(/\?/, '/gps_tracker?') || mongoUri + '/gps_tracker';
  }
  
  mongoose.connect(mongoUri, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10
  })
  .then(() => {
    console.log('✅ Conectado a MongoDB Atlas correctamente!');
  })
  .catch(err => {
    console.error('❌ Error conectando a MongoDB:', err.message);
    console.log('⚠️ Continuando sin MongoDB...');
  });
}

// ==================== ESQUEMAS ====================
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  username: { type: String, index: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  accuracy: Number,
  timestamp: { type: Date, default: Date.now, index: true }
});

const Location = mongoose.model('Location', locationSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  deviceId: { type: String, unique: true, sparse: true, index: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

userSchema.methods.comparePassword = function(password) {
  return this.password === password;
};

const User = mongoose.model('User', userSchema);

// ==================== RUTAS PÚBLICAS ====================

// Health check
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  const statusCode = dbStatus === 'connected' ? 200 : 503;
  
  res.status(statusCode).json({
    status: dbStatus === 'connected' ? 'ok' : 'error',
    timestamp: new Date().toISOString(),
    service: 'gps-tracker-api',
    version: '2.0.0',
    database: dbStatus,
    uptime: process.uptime()
  });
});

// Ruta principal
app.get('/', (req, res) => {
  res.json({
    message: '🚀 GPS Tracker API - Railway',
    status: 'running',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    endpoints: {
      public: [
        'GET  /',
        'GET  /health',
        'GET  /api/cors-test',
        'POST /api/login',
        'POST /api/register'
      ],
      protected: [
        'POST /api/location',
        'GET  /api/locations/:userId',
        'GET  /api/admin/users',
        'GET  /api/admin/user/:userId/locations',
        'GET  /api/admin/user/:userId/stats'
      ]
    }
  });
});

// Test CORS
app.get('/api/cors-test', (req, res) => {
  res.json({
    success: true,
    message: '✅ CORS funcionando correctamente!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'Sin origen'
  });
});

// ==================== AUTENTICACIÓN ====================

// Login
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login request from:', req.headers.origin);
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario y contraseña requeridos' 
      });
    }
    
    let user = await User.findOne({ username: username.trim() });
    if (!user) {
      user = await User.findOne({ email: username.trim().toLowerCase() });
    }
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }
    
    if (user.password !== password) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }
    
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });
    
    const token = jwt.sign(
      { 
        id: user._id, 
        username: user.username,
        deviceId: user.deviceId,
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret-key-12345',
      { expiresIn: '7d' }
    );
    
    console.log('✅ Login exitoso para:', user.username);
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        deviceId: user.deviceId,
        role: user.role,
        email: user.email
      },
      token
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error en el servidor' 
    });
  }
});

// Registro
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    console.log('📝 Register request:', { username, email });
    
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Todos los campos son requeridos' 
      });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario o email ya registrados' 
      });
    }
    
    const deviceId = `device_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const user = new User({
      username,
      email: email.toLowerCase(),
      password,
      deviceId
    });
    
    await user.save();
    
    const token = jwt.sign(
      { 
        id: user._id, 
        username: user.username,
        deviceId: user.deviceId,
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret-key-12345',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Usuario registrado exitosamente',
      user: {
        id: user._id,
        username: user.username,
        deviceId: user.deviceId,
        role: user.role,
        email: user.email
      },
      token
    });
    
  } catch (error) {
    console.error('❌ Register error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error en el servidor' 
    });
  }
});

// ==================== RUTAS DE UBICACIÓN ====================

// Guardar ubicación
app.post('/api/location', async (req, res) => {
  try {
    const { userId, latitude, longitude, accuracy } = req.body;
    
    console.log('📍 Location from:', userId);
    
    if (!userId || latitude === undefined || longitude === undefined) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }
    
    let username = userId;
    const user = await User.findOne({ deviceId: userId });
    if (user) username = user.username;
    
    const location = new Location({
      userId,
      username,
      latitude,
      longitude,
      accuracy: accuracy || 0
    });
    
    await location.save();
    
    // WebSocket - Emitir a todos
    const locationData = {
      userId,
      username,
      latitude,
      longitude,
      accuracy: accuracy || 0,
      timestamp: new Date()
    };
    
    io.emit('locationUpdate', locationData);
    
    // Emitir a sala de admin
    io.to('admin-room').emit('adminLocationUpdate', {
      ...locationData,
      deviceId: userId,
      userInfo: user ? {
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
      } : null
    });
    
    res.json({
      success: true,
      message: 'Ubicación guardada',
      locationId: location._id
    });
    
  } catch (error) {
    console.error('❌ Location error:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Obtener ubicaciones de un usuario (para app móvil)
app.get('/api/locations/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 50 } = req.query;
    
    const locations = await Location.find({ userId })
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    res.json(locations);
  } catch (error) {
    res.status(500).json([]);
  }
});

// ==================== RUTAS DE ADMINISTRADOR ====================

// Obtener todos los usuarios con estadísticas
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username email role deviceId createdAt lastLogin');
    
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        if (!user.deviceId) {
          return {
            userId: 'no-device',
            username: user.username,
            email: user.email,
            role: user.role,
            locationCount: 0,
            lastSeen: user.lastLogin || user.createdAt,
            firstSeen: user.createdAt,
            lastLocation: null,
            deviceId: user.deviceId
          };
        }
        
        const lastLocation = await Location.findOne({ userId: user.deviceId })
          .sort({ timestamp: -1 })
          .limit(1);
        
        const locationCount = await Location.countDocuments({ userId: user.deviceId });
        
        const firstLocation = await Location.findOne({ userId: user.deviceId })
          .sort({ timestamp: 1 })
          .limit(1);
        
        return {
          userId: user.deviceId,
          username: user.username,
          email: user.email,
          role: user.role,
          locationCount: locationCount || 0,
          lastSeen: lastLocation ? lastLocation.timestamp : user.lastLogin || user.createdAt,
          firstSeen: firstLocation ? firstLocation.timestamp : user.createdAt,
          lastLocation: lastLocation ? {
            latitude: lastLocation.latitude,
            longitude: lastLocation.longitude,
            accuracy: lastLocation.accuracy,
            timestamp: lastLocation.timestamp
          } : null,
          deviceId: user.deviceId
        };
      })
    );
    
    // Filtrar solo usuarios con ubicaciones para admin
    const usersWithLocations = usersWithStats.filter(user => 
      user.locationCount > 0 && user.userId !== 'no-device'
    );
    
    res.json(usersWithLocations);
  } catch (error) {
    console.error('❌ Admin users error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error obteniendo usuarios',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Obtener historial de ubicaciones de un usuario (PARA ADMIN)
app.get('/api/admin/user/:userId/locations', async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 500, startDate, endDate } = req.query;
    
    console.log(`📊 Historial solicitado para: ${userId}, límite: ${limit}`);
    
    const query = { userId };
    
    if (startDate) {
      query.timestamp = { $gte: new Date(startDate) };
    }
    if (endDate) {
      query.timestamp = { 
        ...query.timestamp, 
        $lte: new Date(endDate) 
      };
    }
    
    const locations = await Location.find(query)
      .sort({ timestamp: 1 })
      .limit(parseInt(limit));
    
    console.log(`✅ ${locations.length} ubicaciones encontradas para ${userId}`);
    
    const formattedLocations = locations.map(loc => ({
      userId: loc.userId,
      username: loc.username || 'Sin nombre',
      latitude: loc.latitude,
      longitude: loc.longitude,
      accuracy: loc.accuracy || 0,
      timestamp: loc.timestamp,
      formattedTime: loc.timestamp.toLocaleString()
    }));
    
    res.json(formattedLocations);
  } catch (error) {
    console.error('❌ Error obteniendo historial:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo historial',
      message: error.message
    });
  }
});

// Obtener estadísticas de usuario
app.get('/api/admin/user/:userId/stats', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const allLocations = await Location.find({ userId })
      .sort({ timestamp: 1 });
    
    if (allLocations.length === 0) {
      return res.json({
        success: true,
        message: 'Usuario sin ubicaciones',
        stats: {
          totalLocations: 0,
          firstLocation: null,
          lastLocation: null,
          dateRange: null,
          avgAccuracy: 0
        }
      });
    }
    
    const firstLocation = allLocations[0];
    const lastLocation = allLocations[allLocations.length - 1];
    const avgAccuracy = allLocations.reduce((sum, loc) => sum + (loc.accuracy || 0), 0) / allLocations.length;
    
    res.json({
      success: true,
      stats: {
        totalLocations: allLocations.length,
        firstLocation: {
          latitude: firstLocation.latitude,
          longitude: firstLocation.longitude,
          timestamp: firstLocation.timestamp,
          accuracy: firstLocation.accuracy
        },
        lastLocation: {
          latitude: lastLocation.latitude,
          longitude: lastLocation.longitude,
          timestamp: lastLocation.timestamp,
          accuracy: lastLocation.accuracy
        },
        dateRange: {
          start: firstLocation.timestamp,
          end: lastLocation.timestamp,
          days: Math.ceil((lastLocation.timestamp - firstLocation.timestamp) / (1000 * 60 * 60 * 24))
        },
        avgAccuracy: avgAccuracy.toFixed(2)
      }
    });
  } catch (error) {
    console.error('❌ Error en stats:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Eliminar ubicaciones de usuario
app.delete('/api/admin/user/:userId/locations', async (req, res) => {
  try {
    const { userId } = req.params;
    const { beforeDate } = req.query;
    
    const query = { userId };
    if (beforeDate) {
      query.timestamp = { $lt: new Date(beforeDate) };
    }
    
    const result = await Location.deleteMany(query);
    
    res.json({
      success: true,
      message: `Eliminadas ${result.deletedCount} ubicaciones`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== SOCKET.IO EVENTOS ====================

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);
  
  // Unirse a sala de admin
  socket.on('join-admin-room', () => {
    socket.join('admin-room');
    console.log('👨‍💼 Admin conectado:', socket.id);
    
    // Notificar a todos los admin que hay un nuevo admin conectado
    socket.to('admin-room').emit('admin-connected', { adminId: socket.id });
  });
  
  // Registrar usuario
  socket.on('register-user', (data) => {
    console.log('👤 User registered:', data?.userId);
    
    // Notificar a los admin
    io.to('admin-room').emit('user-registered', {
      userId: data.userId,
      username: data.username,
      timestamp: new Date(),
      socketId: socket.id
    });
  });
  
  // Obtener usuarios en tiempo real
  socket.on('get-users', async () => {
    try {
      const users = await User.find({}, 'username deviceId lastLogin');
      const usersWithStatus = users.map(user => ({
        userId: user.deviceId,
        username: user.username,
        lastSeen: user.lastLogin,
        isOnline: false // Podrías implementar lógica de online/offline
      }));
      
      socket.emit('users-list', usersWithStatus);
    } catch (error) {
      console.error('Error obteniendo usuarios:', error);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Socket disconnected:', socket.id);
    
    // Notificar a admin que un usuario se desconectó
    io.to('admin-room').emit('user-disconnected', { socketId: socket.id });
  });
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Ruta no encontrada',
    path: req.path,
    method: req.method,
    availableEndpoints: [
      '/',
      '/health',
      '/api/cors-test',
      '/api/login',
      '/api/register',
      '/api/location',
      '/api/locations/:userId',
      '/api/admin/users',
      '/api/admin/user/:userId/locations',
      '/api/admin/user/:userId/stats'
    ]
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    timestamp: new Date().toISOString()
  });
});

// ==================== INICIAR SERVIDOR ====================
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(60));
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🌍 Health Check: http://0.0.0.0:${PORT}/health`);
  console.log(`🔗 Railway URL: https://gpsbackend-production.up.railway.app`);
  console.log(`⚡ Entorno: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
  console.log('='.repeat(60));
});