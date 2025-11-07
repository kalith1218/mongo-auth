import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import User from "../models/User.js";

const router = express.Router();

// JWT verify middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Login rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 5,
  message: "Too many login attempts. Try again after 15 minutes.",
});

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role, adminCode, imageUrl } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    let userRole = role;
    if (role === "admin" && adminCode !== process.env.ADMIN_CODE)
      return res.status(403).json({ message: "Invalid admin code" });
    else if (role !== "admin") userRole = "user";

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: userRole,
      imageUrl,
    });
    await user.save();

    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// LOGIN
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password" });

    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    user.refreshToken = refreshToken;
    await user.save();

    res.json({ id: user._id, accessToken, refreshToken, role: user.role });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// REFRESH TOKEN
router.post("/refresh", async (req, res) => {
  const { token } = req.body;
  if (!token)
    return res.status(401).json({ message: "No refresh token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== token)
      return res.status(403).json({ message: "Invalid refresh token" });

    const newAccessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    res.json({ accessToken: newAccessToken });
  } catch {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

// GET USERS (admin sees all, user sees own)
router.get("/", verifyToken, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      const users = await User.find({}, "-password -refreshToken");
      res.json(users);
    } else {
      const user = await User.findById(req.user.id, "-password -refreshToken");
      res.json(user);
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// UPDATE USER (admin only)
router.put("/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Access denied" });
  const { name, role, imageUrl } = req.body;
  await User.findByIdAndUpdate(req.params.id, { name, role, imageUrl });
  res.json({ message: "User updated" });
});

// DELETE USER (admin only)
router.delete("/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Access denied" });
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "User deleted" });
});

// GET a single profile by ID — Only admin can access
router.get("/api/:id", verifyToken, async (req, res) => {
  try {
    // Ensure only admin can access
    if (req.user.role !== "admin") {
      return res.status(403).json({
        message: `access denied because you are a ${req.user.role}`,
      });
    }

    const user = await User.findById(
      req.params.id,
      "-password -refreshToken"
    );
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;


// {
//       "_id": "6900c97a276414474fa70570",
//       "name": "arunUser",
//       "email": "arunUserwebdev@gmail.com",
//       "role": "user",
//       "imageUrl": "heyIrl",
//       "__v": 0
//   },

// {
//       "_id": "6900ca09276414474fa70574",
//       "name": "arunAdmin",
//       "email": "arunAdminwebdev@gmail.com",
//       "role": "admin",
//       "imageUrl": "heyIrl",
//       "__v": 0
//   },

// when we give the access token for the first time we will create token using

// {
// id: of the object
// issue of tokem time,
// expiry time
// }/becomes special charactrer

// sad21212wasdqwqwq

// role

// 1-> access token expired
// 2.> admin trying to edit some object
// 3-> he cannot do that, because access token expired
// 4 -> the we send him to refresh route to get a new access token
// 5-> admin gives the access token to refresh route? no he need not give the access token it should be in trash,
// 6-> refresh route ask for refresh token
// 7 => so admin gives the refresh token, refresh route
// 8  => refresh will verify the refresh token that he got from admin and then it will verify with env jwt refresh token
// if everything matches, refresh route takes the id of the admin who gave the refresh token from the token itself
// and then go to DB and ask for the admins whole object
// from that he can extract the role and id and supply new access token

// {"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5MDhjNjJhZDM4YWYzODAyNTIzMzA1YSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc2MjE4MjcxMiwiZXhwIjoxNzYyMTgyNzcyfQ.kCYJKGXVcNn3kREp9YvVL6B5ZzGmY18rlNq-Z1WKRzQ","refreshToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5MDhjNjJhZDM4YWYzODAyNTIzMzA1YSIsImlhdCI6MTc2MjE4MjcxMiwiZXhwIjoxNzYyMzU1NTEyfQ.WJCHgIFPvHIOabwDqHYmTN5Xd0LIMkFXraHgoGHckm8","role":"admin"}
