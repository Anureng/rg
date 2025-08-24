const passport = require('passport');
const { signAccessToken, signRefreshToken } = require('../utils/jwt');
const User = require('../models/User');

exports.googleCallback = (req, res) => {
  // user is attached by passport
  const user = req.user;
  const access = signAccessToken(user);
  signRefreshToken(user, req).then(refresh => {
    res.redirect(`${process.env.APP_URL}/oauth-success?token=${access}&refreshToken=${refresh}`);
  });
};

exports.githubCallback = (req, res) => {
  const user = req.user;
  const access = signAccessToken(user);
  signRefreshToken(user, req).then(refresh => {
    res.redirect(`${process.env.APP_URL}/oauth-success?token=${access}&refreshToken=${refresh}`);
  });
};