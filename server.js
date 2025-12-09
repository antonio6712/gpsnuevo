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
  cors: {  // CORREGIDO: quita la 'd' que está de más
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);
  
  socket.on('register-user', (data) => {
    console.log('👤 User registered:', data?.userId);
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Socket disconnected:', socket.id);
  });
});

// ==================== CORS CONFIGURACIÓN ====================
const corsOptions = {
  origin: function (origin, callback) {
    // Permitir estos orígenes específicamente
    const allowedOrigins = [
      'https://comforting-strudel-cb2b2f.netlify.app',
      'http://localhost:8080',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      // Añade aquí tu dominio de Railway cuando lo tengas
    ];
    
    // En Railway, a veces el origin viene como undefined
    if (!origin) {
      return callback(null, true);
    }
    
    // Para desarrollo, permitir cualquier origen
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    // En producción, verificar los orígenes permitidos
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('⚠️ Origen bloqueado:', origin);
      callback(null, true); // Temporalmente permitir todo
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  optionsSuccessStatus: 200
};

// Usar middleware de CORS
app.use(cors(corsOptions));

// MIDDLEWARE para logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url} - Origin: ${req.headers.origin || 'No origin'}`);
  next();
});

app.use(express.json());

// ==================== CONEXIÓN A MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI || '';

console.log('='.repeat(60));
console.log('🚀 INICIANDO GPS TRACKER API - RAILWAY');
console.log('='.repeat(60));
console.log('🔍 Variables de entorno:');
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
console.log(`   PORT: ${process.env.PORT || 3000}`);
console.log(`   RAILWAY_PUBLIC_DOMAIN: ${process.env.RAILWAY_PUBLIC_DOMAIN || 'N/A'}`);
console.log(`   MONGODB_URI: ${MONGODB_URI ? '✓ PRESENTE' : '✗ FALTANTE!'}`);
console.log('='.repeat(60));

// Health check mejorado - DEBE SER LO PRIMERO
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  const statusCode = dbStatus === 'connected' ? 200 : 503;
  
  res.status(statusCode).json({
    status: dbStatus === 'connected' ? 'ok' : 'error',
    timestamp: new Date().toISOString(),
    service: 'gps-tracker-api',
    version: '1.0.0',
    database: dbStatus,
    uptime: process.uptime()
  });
});

// Verificar MongoDB URI
if (!MONGODB_URI) {
  console.error('❌ ERROR: MONGODB_URI no está definida');
  console.log('⚠️ Continuando sin conexión a MongoDB...');
} else {
  console.log('🔗 Conectando a MongoDB Atlas...');
  
  // Añadir nombre de base de datos si no existe
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
  userId: { type: String, required: true },
  username: { type: String },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  accuracy: Number,
  timestamp: { type: Date, default: Date.now }
});

const Location = mongoose.model('Location', locationSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  deviceId: { type: String, unique: true, sparse: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

userSchema.methods.comparePassword = function(password) {
  return this.password === password;
};

const User = mongoose.model('User', userSchema);

// ==================== RUTAS ====================

// Ruta principal
app.get('/', (req, res) => {
  res.json({
    message: '🚀 GPS Tracker API - Railway',
    status: 'running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
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
        'GET  /api/admin/users'
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
    origin: req.headers.origin || 'Sin origen',
    allowedOrigins: [
      'https://comforting-strudel-cb2b2f.netlify.app',
      'http://localhost:8080',
      'http://localhost:3000'
    ]
  });
});

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
    
    // Buscar usuario
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
    
    // Actualizar último login
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });
    
    // Generar token
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
        role: user.role
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
    
    // Verificar si existe
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario o email ya registrados' 
      });
    }
    
    // Crear usuario
    const deviceId = `device_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const user = new User({
      username,
      email: email.toLowerCase(),
      password,
      deviceId
    });
    
    await user.save();
    
    // Generar token
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
        role: user.role
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

// Guardar ubicación
app.post('/api/location', async (req, res) => {
  try {
    const { userId, latitude, longitude, accuracy } = req.body;
    
    console.log('📍 Location from:', userId);
    
    if (!userId || latitude === undefined || longitude === undefined) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }
    
    // Buscar username
    let username = userId;
    const user = await User.findOne({ deviceId: userId });
    if (user) username = user.username;
    
    // Guardar en BD
    const location = new Location({
      userId,
      username,
      latitude,
      longitude,
      accuracy: accuracy || 0
    });
    
    await location.save();
    
    // WebSocket
    io.emit('locationUpdate', {
      userId,
      username,
      latitude,
      longitude,
      accuracy: accuracy || 0,
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      message: 'Ubicación guardada'
    });
    
  } catch (error) {
    console.error('❌ Location error:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Obtener ubicaciones
app.get('/api/locations/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const locations = await Location.find({ userId })
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json(locations);
  } catch (error) {
    res.json([]);
  }
});

// Admin: usuarios
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username email role deviceId createdAt lastLogin');
    
    const usersWithLocations = await Promise.all(
      users.map(async (user) => {
        const lastLocation = await Location.findOne({ userId: user.deviceId })
          .sort({ timestamp: -1 })
          .limit(1);
        
        return {
          userId: user.deviceId,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLocation: lastLocation ? {
            latitude: lastLocation.latitude,
            longitude: lastLocation.longitude
          } : null
        };
      })
    );
    
    res.json(usersWithLocations);
  } catch (error) {
    console.error('Admin users error:', error);
    res.json([]);
  }
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Ruta no encontrada',
    path: req.path,
    method: req.method
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== INICIAR SERVIDOR ====================
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(60));
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🌍 Health Check: http://0.0.0.0:${PORT}/health`);
  console.log(`🔗 Railway URL: ${process.env.RAILWAY_PUBLIC_DOMAIN || 'N/A'}`);
  console.log(`⚡ Entorno: ${process.env.NODE_ENV || 'development'}`);
  console.log('='.repeat(60));
  
  // Test self-connection
  console.log('🔄 Probando conexión interna...');
});