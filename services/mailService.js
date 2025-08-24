const nodemailer = require('nodemailer');
const crypto = require('crypto');

// In-memory token stores for demo; move to Redis for prod
const emailTokens = new Map();
const resetTokens = new Map();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

exports.sendEmailVerification = async (email, url, token) => {
  emailTokens.set(`${email}:${token}`, Date.now() + 1000 * 60 * 30);
  await transporter.sendMail({ from: process.env.MAIL_FROM, to: email, subject: 'Verify your email', html: `<a href='${url}'>Verify Email</a>` });
};

exports.verifyEmailToken = async (email, token) => {
  const key = `${email}:${token}`;
  const exp = emailTokens.get(key);
  if (exp && exp > Date.now()) { emailTokens.delete(key); return true; }
  return false;
};

exports.sendPasswordReset = async (email, url, token) => {
  resetTokens.set(`${email}:${token}`, Date.now() + 1000 * 60 * 30);
  await transporter.sendMail({ from: process.env.MAIL_FROM, to: email, subject: 'Reset your password', html: `<a href='${url}'>Reset Password</a>` });
};

exports.verifyPasswordResetToken = async (email, token) => {
  const key = `${email}:${token}`;
  const exp = resetTokens.get(key);
  if (exp && exp > Date.now()) { resetTokens.delete(key); return true; }
  return false;
};