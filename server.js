const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ==================== CORS PARA RAILWAY ====================
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

// MIDDLEWARE ESPECIAL para logging de CORS (opcional)
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - Origin: ${req.headers.origin || 'No origin'}`);
  next();
});

app.use(express.json());

// ==================== CONEXIÓN A MONGODB ====================
const MONGODB_URI = process.env.MONGODB_URI;

console.log('='.repeat(50));
console.log('🔧 INICIANDO SERVIDOR GPS TRACKER - CORS FIXED');
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

// ==================== MIDDLEWARE DE AUTENTICACIÓN ====================
const auth = {
  verifyToken: (req, res, next) => {
    try {
      const token = req.headers['authorization']?.replace('Bearer ', '') || 
                   req.headers['x-auth-token'];
      
      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'Token no proporcionado'
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: 'Token inválido'
      });
    }
  },

  isAdmin: (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({
        success: false,
        error: 'Se requieren permisos de administrador'
      });
    }
  }
};

// ==================== RUTAS PÚBLICAS ====================

// Ruta de prueba CORS
app.get('/api/cors-test', (req, res) => {
  res.json({
    success: true,
    message: '✅ CORS funcionando en Railway!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'Sin origen',
    headers: req.headers,
    cors: {
      'Access-Control-Allow-Origin': res.get('Access-Control-Allow-Origin'),
      'Access-Control-Allow-Methods': res.get('Access-Control-Allow-Methods'),
      'Access-Control-Allow-Headers': res.get('Access-Control-Allow-Headers')
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Ruta principal
app.get('/', (req, res) => {
  res.json({
    message: '🚀 GPS Tracker API - Railway',
    endpoints: {
      public: ['POST /api/login', 'POST /api/register', 'GET /api/cors-test'],
      protected: ['POST /api/location', 'GET /api/admin/users']
    }
  });
});

// ==================== AUTENTICACIÓN ====================

// Login simplificado
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login request from:', req.headers.origin);
    console.log('🔑 Login body:', req.body);
    
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
      process.env.JWT_SECRET || 'secret-key',
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
      process.env.JWT_SECRET || 'secret-key',
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

// ==================== RUTAS RESTANTES ====================

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

// ==================== SOCKET.IO ====================
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
    console.log('👤 User registered:', data?.userId);
  });
  
  socket.on('disconnect', () => {
    console.log('🔌 Socket disconnected:', socket.id);
  });
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Ruta no encontrada'
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor'
  });
});

// ==================== INICIAR SERVIDOR ====================
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(50));
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🌍 CORS habilitado para Netlify y localhost`);
  console.log(`🔗 Endpoint de prueba: http://localhost:${PORT}/api/cors-test`);
  console.log('='.repeat(50));
});