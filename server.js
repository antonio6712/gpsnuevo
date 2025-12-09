const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
require('dotenv').config();

// Importar JWT para autenticación
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

// ==================== CORS MIDDLEWARE MEJORADO PARA RAILWAY ====================
// Middleware de logging para debug
app.use((req, res, next) => {
  console.log(`🌐 ${req.method} ${req.url}`);
  console.log('📨 Origin:', req.headers.origin);
  console.log('📨 Headers:', JSON.stringify(req.headers, null, 2));
  next();
});

// CORS middleware SIMPLIFICADO pero EFECTIVO
app.use((req, res, next) => {
  // Lista de orígenes permitidos
  const allowedOrigins = [
    'https://comforting-strudel-cb2b2f.netlify.app',
    'http://localhost:8080',
    'http://localhost:3000',
    'http://localhost:5173'
  ];
  
  const origin = req.headers.origin;
  
  // Si el origen está en la lista o es undefined, permitirlo
  if (allowedOrigins.includes(origin) || !origin || origin.includes('localhost')) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  } else {
    // Solo para debugging, normalmente no mostrarías esto
    console.log('🚫 Origen no permitido:', origin);
  }
  
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Auth-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Expose-Headers', 'X-Auth-Token');
  
  // IMPORTANTE: Respuesta inmediata para preflight
  if (req.method === 'OPTIONS') {
    console.log('✅ Preflight OPTIONS request handled');
    return res.status(200).end();
  }
  
  next();
});

app.use(express.json());

// ==================== CONEXIÓN A MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/gpstracker';

console.log('='.repeat(50));
console.log('🔧 INICIANDO SERVIDOR GPS TRACKER - RAILWAY EDITION');
console.log('='.repeat(50));
console.log('🔍 Variables de entorno:');
console.log('   NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('   PORT:', process.env.PORT || 3000);
console.log('   MONGODB_URI:', MONGODB_URI ? 'PRESENTE' : 'FALTANTE!');
console.log('='.repeat(50));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  family: 4
})
  .then(() => {
    console.log('✅ Conectado a MongoDB Atlas correctamente!');
  })
  .catch(err => {
    console.error('❌ Error conectando a MongoDB:', err.message);
  });

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

// ==================== RUTAS PÚBLICAS ====================

// Health check para Railway
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Ruta principal
app.get('/', (req, res) => {
  res.json({
    message: '🚀 GPS Tracker API - Railway Deployment',
    cors: 'Enabled',
    endpoints: {
      public: ['POST /api/login', 'POST /api/register', 'GET /health'],
      admin: ['GET /api/admin/users', 'GET /api/admin/user/:userId']
    }
  });
});

// Test de CORS especial para Railway
app.get('/api/cors-test', (req, res) => {
  console.log('🔍 CORS Test Request Headers:', req.headers);
  
  res.json({
    success: true,
    message: '✅ CORS funcionando en Railway!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'No origin',
    yourIp: req.ip,
    corsHeaders: {
      'Access-Control-Allow-Origin': res.get('Access-Control-Allow-Origin') || '*',
      'Access-Control-Allow-Methods': res.get('Access-Control-Allow-Methods'),
      'Access-Control-Allow-Headers': res.get('Access-Control-Allow-Headers')
    }
  });
});

// ==================== AUTENTICACIÓN ====================

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    console.log('📝 Register request body:', req.body);
    
    const { username, email, password } = req.body;
    
    // Validaciones
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Todos los campos son requeridos' 
      });
    }
    
    // Verificar si usuario existe
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
      process.env.JWT_SECRET || 'secret-key-railway',
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

// LOGIN - VERSIÓN SIMPLIFICADA PERO FUNCIONAL
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login request body:', req.body);
    console.log('🔑 Login request headers:', req.headers);
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Usuario y contraseña requeridos' 
      });
    }
    
    // Buscar usuario
    let user = await User.findOne({ username });
    if (!user) {
      user = await User.findOne({ email: username.toLowerCase() });
    }
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }
    
    // Verificar contraseña
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
      process.env.JWT_SECRET || 'secret-key-railway',
      { expiresIn: '7d' }
    );
    
    console.log('✅ Login exitoso para:', username);
    
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

// ==================== RUTAS RESTANTES (MANTENIDAS BREVES) ====================

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
    try {
      const user = await User.findOne({ deviceId: userId });
      if (user) username = user.username;
    } catch (err) {
      // No problem
    }
    
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
    if (io) {
      io.emit('locationUpdate', {
        userId,
        username,
        latitude,
        longitude,
        accuracy: accuracy || 0,
        timestamp: new Date()
      });
    }
    
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

// ==================== WEBSOCKETS ====================

const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);
  
  socket.on('register-user', (data) => {
    console.log('👤 User registered via socket:', data?.userId);
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Socket disconnected:', socket.id);
  });
});

// ==================== INICIAR SERVIDOR ====================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(50));
  console.log(`🚀 Servidor en Railway - Puerto: ${PORT}`);
  console.log('🌍 CORS habilitado para:');
  console.log('   - https://comforting-strudel-cb2b2f.netlify.app');
  console.log('   - Todos los localhost');
  console.log('='.repeat(50));
});