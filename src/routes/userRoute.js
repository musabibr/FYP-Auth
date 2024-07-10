const express = require('express');
const router = express.Router();
const {
    signup,
    sendGreetingEmail,
    login,
    logout,
    forgotPassword,
    resetPassword,
    profile,
    deleteMe,
    uploadUserPhoto,
    updateMe,
    updatePhoto
} = require('../controller/userController');
const { requestOTP, verifyOTP , protect } = require('../middleware/auth');


router.post('/forgot-password', forgotPassword);
router.patch('/reset-password/:resetToken', resetPassword);

router.post('/signup', signup);
router.get('/request-otp/:id', requestOTP);
router.post('/verify-otp/:id', verifyOTP);
router.post('/login', login);
router.get('/logout', logout);


router.use(protect);


router.get('/profile', profile);
router.patch('/update-me',updateMe)
router.patch('/upload-photo',
    uploadUserPhoto,
    updatePhoto)
router.delete('/delete-my-account',deleteMe)


module.exports = router; // Export the router for use in other modules   