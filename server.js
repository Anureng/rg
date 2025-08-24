const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const routes = require('./routes');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const initPassport = require('./config/passport');
const { authLimiter } = require('./middleware/rateLimit');
const errorHandler = require('./middleware/errorHandler');

dotenv.config();
const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || '*', credentials: true }));
app.use(express.json());
app.use(cookieParser());

connectDB();
initPassport();
app.use(passport.initialize());

app.use('/api/auth', authLimiter, routes);
app.get('/health', (req, res) => res.json({ ok: true }));

app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));