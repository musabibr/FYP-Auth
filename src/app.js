require('./config/db');
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require("express-rate-limit");
const hpp = require('hpp');
const mongoSanitize = require("express-mongo-sanitize");

const router = require('./routes/userRoute');

// rate limit
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: 10, // Limit each IP to 10 requests per window
});

// cors allowed origins
const allowedOrigins = [
  "https://psychological-assistant-app.vercel.app/",
  "http://localhost:8085/api/v1/users/",
  "*"
];

const corsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies for authenticated requests (optional)  
};
// creating the server
const app = express();
app.use(cors());
// app.use(limiter)
app.use(express.json());
app.use(hpp())
app.use(morgan('dev'));
app.use(mongoSanitize());

app.use("/api/v1/users/", router);

module.exports = app
