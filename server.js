const express = require('express');
const http = require('http');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ==================== CONFIGURACIÓN BÁSICA ====================
const PORT = process.env.PORT || 8080;

// Log inicial
console.log('='.repeat(60));
console.log('🚀 INICIANDO SERVIDOR GPS TRACKER EN RAILWAY');
console.log('='.repeat(60));
console.log('🔍 Configuración:');
console.log('   PORT:', PORT);
console.log('   NODE_ENV:', process.env.NODE_ENV || 'production');
console.log('   MONGODB_URI:', process.env.MONGODB_URI ? 'PRESENTE' : 'NO DEFINIDA');
console.log('='.repeat(60));

// ==================== CORS SIMPLE PERO EFECTIVO ====================
app.use(cors({
  origin: '*', // Permitir todo temporalmente
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ==================== HEALTH CHECK (OBLIGATORIO PARA RAILWAY) ====================
app.get('/health', (req, res) => {
  console.log('🩺 Health check recibido');
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'gps-tracker-api',
    version: '1.0.0'
  });
});

// ==================== RUTA PRINCIPAL ====================
app.get('/', (req, res) => {
  console.log('🏠 Ruta principal solicitada');
  res.json({
    message: '🚀 GPS Tracker API - Railway',
    status: 'online',
    endpoints: [
      'GET  /health',
      'GET  /api/cors-test',
      'POST /api/login',
      'POST /api/register',
      'POST /api/location',
      'GET  /api/admin/users'
    ],
    documentation: 'API para rastreo GPS en tiempo real'
  });
});

// ==================== TEST CORS ====================
app.get('/api/cors-test', (req, res) => {
  console.log('🌐 CORS Test - Headers:', {
    origin: req.headers.origin,
    'user-agent': req.headers['user-agent']
  });
  
  res.json({
    success: true,
    message: '✅ CORS funcionando correctamente!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'No origin header',
    cors: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    },
    server: 'railway-production',
    status: 'online'
  });
});

// ==================== TEST CONEXIÓN MONGODB (OPCIONAL) ====================
let mongoose;
try {
  mongoose = require('mongoose');
  
  if (process.env.MONGODB_URI) {
    console.log('🔗 Intentando conectar a MongoDB...');
    
    // Conexión simple sin opciones complejas
    mongoose.connect(process.env.MONGODB_URI)
      .then(() => {
        console.log('✅ MongoDB conectado correctamente');
      })
      .catch(err => {
        console.error('❌ Error conectando MongoDB:', err.message);
        console.log('⚠️  La app funcionará sin base de datos');
      });
  } else {
    console.log('⚠️  MONGODB_URI no definida - Modo sin base de datos');
  }
} catch (error) {
  console.log('⚠️  mongoose no disponible - Modo sin base de datos');
}

// ==================== RUTAS DE AUTENTICACIÓN (DEMO) ====================

// Login DEMO
app.post('/api/login', (req, res) => {
  console.log('🔑 Login attempt:', req.body);
  
  // Validación básica
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Usuario y contraseña requeridos'
    });
  }
  
  // DEMO: siempre éxito con usuario 'admin' o cualquier otro
  const isAdmin = username === 'admin';
  
  res.json({
    success: true,
    user: {
      id: Date.now(),
      username: username,
      role: isAdmin ? 'admin' : 'user',
      deviceId: `device_${Date.now()}`
    },
    token: 'demo-jwt-token-' + Date.now(),
    message: 'Login exitoso (modo demo)'
  });
});

// Registro DEMO
app.post('/api/register', (req, res) => {
  console.log('📝 Register attempt:', req.body);
  
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Todos los campos son requeridos'
    });
  }
  
  res.json({
    success: true,
    user: {
      id: Date.now(),
      username: username,
      email: email,
      role: 'user',
      deviceId: `device_${Date.now()}`
    },
    token: 'demo-jwt-token-' + Date.now(),
    message: 'Usuario registrado (modo demo)'
  });
});

// Guardar ubicación DEMO
app.post('/api/location', (req, res) => {
  console.log('📍 Location received:', req.body);
  
  const { userId, latitude, longitude } = req.body;
  
  if (!userId || latitude === undefined || longitude === undefined) {
    return res.status(400).json({
      success: false,
      error: 'userId, latitude y longitude requeridos'
    });
  }
  
  res.json({
    success: true,
    message: 'Ubicación recibida',
    location: {
      userId,
      latitude,
      longitude,
      timestamp: new Date().toISOString()
    }
  });
});

// Admin users DEMO
app.get('/api/admin/users', (req, res) => {
  console.log('👥 Admin users requested');
  
  const demoUsers = [
    {
      userId: 'device_123',
      username: 'admin',
      email: 'admin@example.com',
      role: 'admin',
      lastLocation: {
        latitude: 19.4326,
        longitude: -99.1332,
        timestamp: new Date().toISOString()
      }
    },
    {
      userId: 'device_456',
      username: 'usuario1',
      email: 'user1@example.com',
      role: 'user',
      lastLocation: {
        latitude: 19.4340,
        longitude: -99.1350,
        timestamp: new Date().toISOString()
      }
    }
  ];
  
  res.json(demoUsers);
});

// ==================== MANEJO DE ERRORES ====================

// 404 - Ruta no encontrada
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Ruta no encontrada',
    path: req.url,
    method: req.method
  });
});

// Error handler general
app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== INICIAR SERVIDOR ====================

server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor corriendo en http://0.0.0.0:${PORT}`);
  console.log(`🌐 Health check: http://0.0.0.0:${PORT}/health`);
  console.log(`🔗 CORS test: http://0.0.0.0:${PORT}/api/cors-test`);
  console.log('='.repeat(60));
  console.log('🚀 LISTO PARA RECIBIR SOLICITUDES');
  console.log('='.repeat(60));
});

// Manejo de cierre limpio
process.on('SIGTERM', () => {
  console.log('🛑 Recibido SIGTERM, cerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor cerrado');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Recibido SIGINT, cerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor cerrado');
    process.exit(0);
  });
});