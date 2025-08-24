const Joi = require('joi');

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(60).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  mfaToken: Joi.string().optional()
});

const emailSchema = Joi.object({ email: Joi.string().email().required() });

const resetSchema = Joi.object({ email: Joi.string().email().required(), token: Joi.string().required(), newPassword: Joi.string().min(8).required() });

module.exports = { registerSchema, loginSchema, emailSchema, resetSchema };