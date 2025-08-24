const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');

function upsertOAuthUser({ provider, providerId, profile }) {
  return User.findOneAndUpdate(
    { oauthAccounts: { $elemMatch: { provider, providerId } } },
    { $setOnInsert: { name: profile.displayName || 'User', email: profile.emails?.[0]?.value, emailVerified: true }, $addToSet: { oauthAccounts: { provider, providerId } } },
    { upsert: true, new: true }
  );
}

const initPassport = () => {
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => User.findById(id).then(u => done(null, u)).catch(done));

  if (process.env.GOOGLE_CLIENT_ID) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    }, async (accessToken, refreshToken, profile, done) => {
      try { const user = await upsertOAuthUser({ provider: 'google', providerId: profile.id, profile }); done(null, user); } catch (e) { done(e); }
    }));
  }

  if (process.env.GITHUB_CLIENT_ID) {
    passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL
    }, async (accessToken, refreshToken, profile, done) => {
      try { const user = await upsertOAuthUser({ provider: 'github', providerId: profile.id, profile }); done(null, user); } catch (e) { done(e); }
    }));
  }
};

module.exports = initPassport;