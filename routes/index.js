const express = require('express');
const auth = require('./authRoutes');
const oauth = require('./oauthRoutes');

const router = express.Router();
router.use('/auth', auth);
router.use('/oauth', oauth);
module.exports = router;