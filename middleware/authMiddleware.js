const jwt = require('jsonwebtoken');
const ApiKey = require('../models/ApiKey');

module.exports = (required = true) => (req, res, next) => {
  const hdr = req.headers.authorization || '';
  if (!hdr.startsWith('Bearer ')) {
    if (!required) return next();
    return res.status(401).json({ message: 'Unauthorized' });
  }
  const token = hdr.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: decoded.sub, role: decoded.role };
    next();
  } catch (e) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

module.exports.requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ message: 'Forbidden' });
  next();
};

module.exports.apiKeyAuth = async (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ message: 'API key missing' });
  const apiKey = await ApiKey.findOne({ key, active: true });
  if (!apiKey) return res.status(403).json({ message: 'Invalid API key' });
  req.apiKey = apiKey;
  next();
};