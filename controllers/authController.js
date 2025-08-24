const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require('../utils/jwt');
const mail = require('../services/mailService');
const crypto = require('crypto');
const { SiweMessage } = require('siwe');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');

// In-memory nonce for demo; move to Redis in prod
const siweNonces = new Map();

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });
    const user = await User.create({ name, email, password });

    // Email verification token
    const token = crypto.randomBytes(32).toString('hex');
    const verifyUrl = `${process.env.APP_URL}/verify-email?token=${token}&email=${encodeURIComponent(email)}`;
    await mail.sendEmailVerification(email, verifyUrl, token);

    res.status(201).json({ message: 'User registered. Please verify your email.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password, mfaToken } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    if (!user.emailVerified) {
      return res.status(403).json({ message: 'Email not verified' });
    }
    if (user.mfa.enabled) {
      if (!mfaToken) return res.status(401).json({ message: 'MFA token required' });
      const ok = speakeasy.totp.verify({ secret: user.mfa.secret, encoding: 'base32', token: mfaToken, window: 1 });
      if (!ok) return res.status(401).json({ message: 'Invalid MFA token' });
    }

    const access = signAccessToken(user);
    const refresh = await signRefreshToken(user, req);

    res.status(200).json({ token: access, refreshToken: refresh, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = await verifyRefreshToken(refreshToken);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: 'Invalid refresh token' });

    const access = signAccessToken(user);
    const newRefresh = await signRefreshToken(user, req, refreshToken); // rotates & revokes old

    res.json({ token: access, refreshToken: newRefresh });
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
};

exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) await RefreshToken.findOneAndUpdate({ token: refreshToken }, { revoked: true });
    res.json({ message: 'Logged out' });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.me = async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json({ user });
};

exports.verifyEmail = async (req, res) => {
  const { email, token } = req.body;
  const ok = await mail.verifyEmailToken(email, token);
  if (!ok) return res.status(400).json({ message: 'Invalid token' });
  await User.updateOne({ email }, { $set: { emailVerified: true } });
  res.json({ message: 'Email verified' });
};

exports.resendVerification = async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString('hex');
  const verifyUrl = `${process.env.APP_URL}/verify-email?token=${token}&email=${encodeURIComponent(email)}`;
  await mail.sendEmailVerification(email, verifyUrl, token);
  res.json({ message: 'Verification email sent' });
};

exports.requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString('hex');
  const resetUrl = `${process.env.APP_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
  await mail.sendPasswordReset(email, resetUrl, token);
  res.json({ message: 'Password reset email sent' });
};

exports.resetPassword = async (req, res) => {
  const { email, token, newPassword } = req.body;
  const ok = await mail.verifyPasswordResetToken(email, token);
  if (!ok) return res.status(400).json({ message: 'Invalid token' });
  const user = await User.findOne({ email });
  user.password = newPassword;
  await user.save();
  res.json({ message: 'Password updated' });
};

exports.enableMfa = async (req, res) => {
  const user = await User.findById(req.user.id);
  const secret = speakeasy.generateSecret({ name: 'AytesAuth' });
  const otpAuthUrl = secret.otpauth_url;
  const qr = await QRCode.toDataURL(otpAuthUrl);
  user.mfa.secret = secret.base32;
  await user.save();
  res.json({ qr, secret: secret.base32 });
};

exports.verifyMfa = async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user.id);
  const ok = speakeasy.totp.verify({ secret: user.mfa.secret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(400).json({ message: 'Invalid token' });
  user.mfa.enabled = true;
  await user.save();
  res.json({ message: 'MFA enabled' });
};

exports.siweNonce = (req, res) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  siweNonces.set(nonce, Date.now());
  res.json({ nonce });
};

exports.siweVerify = async (req, res) => {
  try {
    const { message, signature } = req.body;
    const msg = new SiweMessage(message);
    const fields = await msg.verify({ signature });
    if (!siweNonces.has(fields.data.nonce)) return res.status(400).json({ message: 'Invalid nonce' });
    siweNonces.delete(fields.data.nonce);

    let user = await User.findOne({ 'wallets.address': fields.data.address.toLowerCase() });
    if (!user) user = await User.create({ name: 'Web3 User', email: `${fields.data.address}@web3.local`, wallets: [{ chain: 'EVM', address: fields.data.address.toLowerCase() }], emailVerified: true });

    const access = signAccessToken(user);
    const refresh = await signRefreshToken(user, req);
    res.json({ token: access, refreshToken: refresh, user: { id: user._id, email: user.email } });
  } catch (e) {
    res.status(400).json({ message: 'SIWE verification failed' });
  }
};