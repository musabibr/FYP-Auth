const express = require('express');
const router = express.Router();
const { signup ,sendGreetingEmail,login ,logout, forgotPassword ,resetPassword, profile} = require('../controller/userController');
const { requestOTP, verifyOTP , protect } = require('../middleware/auth');


router.post('/signup', signup);
router.get('/request-otp/:id', requestOTP);
router.post('/verify-otp/:id', verifyOTP);
router.post('/login', login);
router.get('/logout', logout);

router.post('/forgot-password', forgotPassword);
router.patch('/reset-password/:id', resetPassword);

router.use(protect);


router.get('/profile', profile);


module.exports = router; //  