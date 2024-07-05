const express = require('express');
const router = express.Router();
const { signup ,sendGreetingEmail } = require('../controller/userController');
const { requestOTP, verifyOTP  } = require('../middleware/auth');


router.post('/signup', signup ,sendGreetingEmail);
router.get('/request-otp/:id', requestOTP);
router.post('/verify-otp/:id', verifyOTP);

module.exports = router; 