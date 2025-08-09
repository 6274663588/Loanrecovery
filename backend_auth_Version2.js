const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change_this_secret';

function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: "No token" });
  try {
    const payload = jwt.verify(token, SECRET);
    if (payload.role !== 'admin') throw new Error('Not admin');
    next();
  } catch (e) {
    res.status(403).json({ ok: false, error: "Forbidden" });
  }
}

module.exports = { authenticateAdmin, SECRET };