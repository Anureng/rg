const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/RefreshToken');
const { v4: uuidv4 } = require('uuid');
const UAParser = require('ua-parser-js');

exports.signAccessToken = (user) => {
  return jwt.sign({ sub: user._id.toString(), role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

exports.signRefreshToken = async (user, req, oldToken) => {
  if (oldToken) await RefreshToken.findOneAndUpdate({ token: oldToken }, { revoked: true });
  const token = uuidv4();
  const ua = new UAParser(req.headers['user-agent']).getResult();
  await RefreshToken.create({ user: user._id, token, expiresAt: new Date(Date.now() + 1000*60*60*24*30), userAgent: ua.ua, ip: req.ip });
  return token;
};

exports.verifyRefreshToken = async (token) => {
  const doc = await RefreshToken.findOne({ token, revoked: false });
  if (!doc || doc.expiresAt < new Date()) throw new Error('Invalid');
  return { sub: doc.user.toString() };
};