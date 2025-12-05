// server.js
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "./models/User.js";
import 'dotenv/config';
import mongoose from "mongoose";

const app = express();
app.use(express.json());
app.use(cors());

// ---------------- MongoDB Atlas Connection ----------------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB Atlas Connected"))
.catch(err => console.log("MongoDB Connection Error:", err));

// ---------------- Middleware ----------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// ---------------- AUTH Routes ----------------

// REGISTER
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if(!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const existingUser = await User.findOne({ email });
    if(existingUser) return res.status(400).json({ error: "Email already exists" });

    const user = new User({ name, email, password });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "User registered", token, user: { name: user.name, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if(!email || !password) return res.status(400).json({ error: "Email & password required" });

    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ error: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "Login successful", token, user: { name: user.name, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- CRUD Routes ----------------

// CREATE USER (Protected)
app.post("/create-user", authenticateToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if(!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const existingUser = await User.findOne({ email });
    if(existingUser) return res.status(400).json({ error: "Email already exists" });

    const user = new User({ name, email, password });
    await user.save();
    res.json({ message: "User created", user: { name: user.name, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET USERS (Protected)
app.get("/get-users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE USER (Protected)
app.put("/update-user/:id", authenticateToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const body = {};
    if(name) body.name = name;
    if(email) body.email = email;
    if(password) body.password = await bcrypt.hash(password, 10);

    const user = await User.findByIdAndUpdate(req.params.id, body, { new: true });
    if(!user) return res.status(404).json({ error: "User not found" });

    res.json({ message: "User updated", user: { name: user.name, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE USER (Protected)
app.delete("/delete-user/:id", authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if(!user) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- Start Server ----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
