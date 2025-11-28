// ============================================================
// ======================  IMPORTS  ===========================
// ============================================================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "IEF_SUPER_SECRET_KEY_2025";

// Upload directory
const UPLOADS_DIR = path.join(__dirname, "uploads");
(async () => {
  try { await fs.mkdir(UPLOADS_DIR, { recursive: true }); }
  catch (e) { console.error("mkdir error:", e); }
})();
app.use("/uploads", express.static(UPLOADS_DIR));

// ============================================================
// ====================== DATABASE SETUP =======================
// ============================================================
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/kec_ief";
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

const { Schema, model } = mongoose;

// ============================================================
// ====================== LOGIN SCHEMAS ========================
// ============================================================

// Student Login
const StudentLoginSchema = new Schema({
  rollNo: { type: String, required: true, unique: true },
  emailKongu: { type: String, required: true },
  password: { type: String, required: true }
});
const StudentUser = model("StudentUser", StudentLoginSchema);

// Staff Login
const StaffLoginSchema = new Schema({
  emailKongu: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const StaffUser = model("StaffUser", StaffLoginSchema);

// Admin (future)
const AdminLoginSchema = new Schema({
  email: String,
  password: String
});
const AdminUser = model("AdminUser", AdminLoginSchema);

// ============================================================
// ======================== LOGIN ROUTES =======================
// ============================================================

// ============================================================
// ============= FIXED LOGIN ROUTES USING UserModel ===========
// ============================================================

// STUDENT LOGIN
app.post("/api/login/student", async (req, res) => {
  try {
    const { rollNo, password } = req.body;

    // Student username = rollNo
    const user = await UserModel.findOne({ username: rollNo, role: "student" });

    if (!user) return res.json({ success: false, msg: "Invalid roll number" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, msg: "Incorrect password" });

    const token = jwt.sign({ userId: user._id, type: "student" }, JWT_SECRET, {
      expiresIn: "2d"
    });

    res.json({ success: true, token });

  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  }
});

// STAFF LOGIN
app.post("/api/login/staff", async (req, res) => {
  try {
    const { emailKongu, password } = req.body;

    // Staff username = email
    const user = await UserModel.findOne({ username: emailKongu, role: "staff" });

    if (!user) return res.json({ success:false, msg:"Invalid staff email" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success:false, msg:"Incorrect password" });

    const token = jwt.sign({ userId: user._id, type: "staff" }, JWT_SECRET, {
      expiresIn: "2d"
    });

    res.json({ success:true, token });

  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  }
});

// ============================================================
// ===================== USER MANAGEMENT =======================
// ============================================================
// (Used by Admin Panel to add/remove login users)

const UserSchema = new Schema({
  role: { type: String, enum: ["student", "staff"], required: true },
  email: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // hashed
  createdAt: { type: Date, default: () => new Date() }
});

const UserModel = model("User", UserSchema);

// CREATE USER (student/staff)
app.post("/api/users", async (req, res) => {
  try {
    const { role, email, username } = req.body;

    if (!role || !email || !username)
      return res.status(400).json({ success: false, error: "Missing fields" });

    if (!email.endsWith("@kongu.edu"))
      return res.status(400).json({ success: false, error: "Invalid email domain" });

    // Password = Username
    const hashed = await bcrypt.hash(username, 10);

    const existing = await UserModel.findOne({ username });
    if (existing)
      return res.status(400).json({ success: false, error: "Username already exists" });

    const newUser = new UserModel({
      role,
      email,
      username,
      password: hashed
    });

    await newUser.save();
    res.status(201).json({ success: true, item: newUser });

  } catch (err) {
    console.error("POST /api/users error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// LIST USERS
app.get("/api/users", async (_, res) => {
  try {
    const items = await UserModel.find().sort({ createdAt: -1 }).lean();
    res.json({ success: true, items });
  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  }
});

// DELETE USER
app.delete("/api/users/:id", async (req, res) => {
  try {
    await UserModel.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  }
});

// ============================================================
// =============== YOUR EXISTING MODULE ROUTES =================
// ============================================================

// OD, Events, Members (unchanged code goes here)
// DO NOT remove your existing working logic
// (I am not rewriting these, keep your existing versions)


// ============================================================
// =================== MULTER (unchanged) ======================
// ============================================================
const storage = multer.diskStorage({
  destination: (_,__,cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => {
    cb(null, `${Date.now()}-${Math.floor(Math.random()*1e9)}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage });

// ============================================================
// ========================= SERVER ============================
// ============================================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
