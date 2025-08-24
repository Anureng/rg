const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  token: { type: String, unique: true },
  expiresAt: { type: Date, index: true },
  revoked: { type: Boolean, default: false },
  userAgent: String,
  ip: String
}, { timestamps: true });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);