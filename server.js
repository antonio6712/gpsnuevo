const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ======================================
// 🔥 CORS GLOBAL – VERSIÓN CORRECTA
// ======================================
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Permite cualquier origen dinámico
  if (origin) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Auth-Token"
  );
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");

  // Preflight
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

/* ================================
   🔗 CONEXIÓN A MONGO
================================ */
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error("❌ ERROR: MONGODB_URI no está definido");
  process.exit(1);
}

mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Conectado a MongoDB Atlas"))
  .catch((err) => {
    console.error("❌ Error conectando a MongoDB:", err);
    process.exit(1);
  });

/* ================================
   📌 ESQUEMA DE USUARIO
================================ */
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ["user", "admin"], default: "user" },
  deviceId: { type: String, unique: true, sparse: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

// Comparador simple (no usas bcrypt)
userSchema.methods.comparePassword = function (password) {
  return this.password === password;
};

const User = mongoose.model("User", userSchema);

/* ================================
   📌 ESQUEMA DE UBICACIONES
================================ */
const locationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  username: String,
  latitude: Number,
  longitude: Number,
  accuracy: Number,
  timestamp: { type: Date, default: Date.now }
});
const Location = mongoose.model("Location", locationSchema);

/* ================================
   🔐 AUTH MIDDLEWARE (opcional)
================================ */
const auth = {
  verifyToken: (req, res, next) => {
    try {
      const token = req.headers["authorization"]?.replace("Bearer ", "") || req.headers["x-auth-token"];
      if (!token) {
        return res.status(401).json({ success: false, error: "Token requerido" });
      }
      req.user = jwt.verify(token, process.env.JWT_SECRET || "secret");
      next();
    } catch (err) {
      return res.status(401).json({ success: false, error: "Token inválido" });
    }
  },
};

/* ================================
   🟦 RUTAS PÚBLICAS
================================ */
app.get("/", (req, res) => {
  res.json({ status: "online", message: "API GPS funcionando correctamente" });
});

/* ================================
   📝 REGISTRO
================================ */
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: "Faltan datos" });
    }

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(400).json({ success: false, error: "Usuario o email ya existe" });

    const deviceId = `device_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const user = new User({ username, email, password, role: role || "user", deviceId });
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, deviceId },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "7d" }
    );

    res.json({ success: true, user, token });

  } catch (err) {
    res.status(500).json({ success: false, error: "Error al registrar", details: err.message });
  }
});

/* ================================
   🔑 LOGIN SIMPLE (sin tokens)
================================ */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  let user = await User.findOne({ username });
  if (!user) user = await User.findOne({ email: username });

  if (!user) return res.status(401).json({ success: false, error: "Usuario no encontrado" });
  if (!user.comparePassword(password)) {
    return res.status(401).json({ success: false, error: "Contraseña incorrecta" });
  }

  user.lastLogin = new Date();
  await user.save({ validateBeforeSave: false });

  const token = jwt.sign(
    { id: user._id, username: user.username, deviceId: user.deviceId },
    process.env.JWT_SECRET || "secret",
    { expiresIn: "7d" }
  );

  res.json({ success: true, user, token });
});

/* ================================
   📍 GUARDAR UBICACIÓN
================================ */
app.post("/api/location", async (req, res) => {
  try {
    const { userId, latitude, longitude, accuracy } = req.body;

    if (!userId || latitude === undefined || longitude === undefined) {
      return res.status(400).json({ success: false, error: "Datos incompletos" });
    }

    const user = await User.findOne({ $or: [{ deviceId: userId }, { _id: userId }, { username: userId }] });

    const location = new Location({
      userId: user?.deviceId || userId,
      username: user?.username || "",
      latitude,
      longitude,
      accuracy
    });

    await location.save();

    res.json({ success: true, message: "Ubicación guardada", location });

  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================================
   ▶️ INICIAR SERVIDOR
================================ */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Servidor escuchando en puerto ${PORT}`));
