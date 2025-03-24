require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('./model.user'); // ✅ since you renamed it

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🌱 MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

const JWT_SECRET = process.env.JWT_SECRET;

function generateTokens(user) {
  const accessToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

// 🆕 Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'User exists' });

    const user = new User({ username, password });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// 🔐 Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await user.comparePassword(password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const tokens = generateTokens(user);
  user.refreshToken = tokens.refreshToken;
  await user.save();

  res.json(tokens);
});

// 🔁 Refresh Token
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const payload = jwt.verify(refreshToken, JWT_SECRET);
    const user = await User.findById(payload.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const tokens = generateTokens(user);
    user.refreshToken = tokens.refreshToken;
    await user.save();

    res.json(tokens);
  } catch {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

// 🔒 Protected Route
app.get('/protected', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.userId);
    res.json({ message: `Welcome, ${user.username}!` });
  } catch {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
});
if (require.main === module) {
  app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
}
// 🔓 Logout (invalidate refresh token)
app.post('/logout', async (req, res) => {
  const token = req.body.refreshToken;
  if (!token) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.userId);
    if (!user || user.refreshToken !== token) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    user.refreshToken = null;
    await user.save();

    res.json({ message: 'Logged out successfully' });
  } catch {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

module.exports = app;

 
