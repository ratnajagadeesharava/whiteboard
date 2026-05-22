const express = require('express');
const authRoutes = require('./routes/auth');
const { authenticateToken } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());

// Public routes
app.use('/api/auth', authRoutes);

// Protected route example
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
