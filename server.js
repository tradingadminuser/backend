
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB Connected"))
.catch(err=>console.log(err));

const User = mongoose.model("User", {
  email: String,
  password: String,
  balance: { type: Number, default: 0 },
  role: { type: String, default: "user" },
  frozen: { type: Boolean, default: false }
});

const auth = async (req,res,next)=>{
  try{
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    next();
  }catch{
    res.status(401).send("Unauthorized");
  }
};

const adminOnly = (req,res,next)=>{
  if(req.user.role !== "admin") return res.status(403).send("Admin only");
  next();
};

app.post("/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);

  const user = await User.create({
    email: req.body.email,
    password: hash
  });

  res.json({
    _id: user._id,
    email: user.email
  });
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Check password
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    // Check JWT secret
    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET missing");
    }

    // Create token
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (err) {
    console.error("LOGIN ERROR:", err.message);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

app.get("/dashboard", auth, (req,res)=>{
  res.json({balance:req.user.balance});
});

app.get("/admin/users", auth, adminOnly, async (req,res)=>{
  const users = await User.find();
  res.json(users);
});

app.listen(5000, ()=>console.log("Server running"));
