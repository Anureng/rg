const express = require('express');
const auth = require('../controllers/authController');
const verify = require('../middleware/authMiddleware');
const { validate } = require('../validators/validate');
const { loginSchema, registerSchema, emailSchema, resetSchema } = require('../validators/schemas');

const router = express.Router();

router.post('/register', validate(registerSchema), auth.register);
router.post('/login', validate(loginSchema), auth.login);
router.post('/refresh', auth.refresh);
router.post('/logout', auth.logout);
router.get('/me', verify(), auth.me);

router.post('/email/verify', auth.verifyEmail);
router.post('/email/resend', validate(emailSchema), auth.resendVerification);
router.post('/password/request-reset', validate(emailSchema), auth.requestPasswordReset);
router.post('/password/reset', validate(resetSchema), auth.resetPassword);

router.post('/mfa/enable', verify(), auth.enableMfa);
router.post('/mfa/verify', verify(), auth.verifyMfa);

// SIWE
router.get('/siwe/nonce', auth.siweNonce);
router.post('/siwe/verify', auth.siweVerify);

module.exports = router;