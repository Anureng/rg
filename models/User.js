const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String },
  role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' },
  emailVerified: { type: Boolean, default: false },
  mfa: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, default: null }
  },
  webauthn: {
    credentials: [{
      credId: String,
      publicKey: String,
      counter: Number
    }]
  },
  wallets: [{ chain: String, address: String }],
  oauthAccounts: [{ provider: String, providerId: String }],
  lastLoginAt: Date,
  lastLoginIp: String
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = function(candidate) {
  if (!this.password) return false;
  return bcrypt.compare(candidate, this.password);
};

module.exports = mongoose.model('User', userSchema);