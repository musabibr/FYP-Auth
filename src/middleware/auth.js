const userRepository = require("../Data_layer/repositories/userRepository");
const Email = require("../utils/email");
const { generateOTP } = require("../utils/OTP"); 
const {generateJWT ,verifyJWT} = require('../middleware/middleware');

const hashData = require("../utils/hashData");
const UserRepository = require("../Data_layer/repositories/userRepository");

/**
 * This function is a middleware for authentication. It is responsible for 
 * verifying a user's account based on the provided information. 
 * 
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} JSON response with account verification status and message
 */
module.exports.requestOTP = async (req, res) => {
    let id, email;
    
    // Check if id is provided in the request parameters
    // if (!req.params.id) {
    //     return res.status(403).json({message: "Forbidden!!"});
    // }
    // const id = req.params.id; // Extract user ID from request parameters

    // Generate OTP
    const otpCode = generateOTP();
    // Encrypt OTP
    const code = await hashData.encryptData(otpCode);

    try {
        let user;
        if (req.params.id) {
        id = req.params.id;
        // Retrieve user from database using user ID
        user = await new userRepository().getUserById(id);
        }
        else if(req.body.email) {
            email = req.body;
            user = new UserRepository().getUser(email)
        }

        // Check if user exists
        if (!user) {
            // If user does not exist, return error response
            return res.status(404).json({ message: "User not found ,Please register" });
        }

        // Check if user is already verified
        if (user.isVerified) {
            // If user is already verified, return error response
            return res.status(400).json({ message: "User already verified" });
        }

        // Check if the user is active
        if (!user.isActive) {
            // If user's account is not active, return error response
            return res.status(400).json({
                message: "Your account has been blocked,contact technical support for further details!!"
            });
        }

        // Check if user has exceeded 6 attempts
        if (user.otp.attempts > 6) {
            // If user has exceeded 6 attempts, deactivate user's account
            await new userRepository().DeactivateAccount(user._id);
            // Return error response
            return res.status(400).json({ message: "Too many attempts." });
        }

        // Update user's OTP and attempts
        user = await new userRepository().updateOtp(user._id, {
            code: code,
            createdAt: Date.now(),
            expiresAt: Date.now() + 15 * 60 * 1000,
        });

        // Send OTP email
        const url = `${req.protocol}://${req.get("host")}/api/v1/users/${
        user._id
        }/verify`;

        // const email =  
            // await new Email(user, url).sendOtp(otpCode);
        // if (!email) {
        //     // If email sending fails, return error response
        //     return res.status(500).json({ message: "Failed to send email" });
        // }

        // Return success response with OTP verification status and message
        return res.status(200).json({
            status: 'success',
            message: "OTP sent successfully",
            id:user._id,
            otp:otpCode,
            attempts: {
                sent: user.otp.attempts - 1,
                remaining: 6 - user.otp.attempts,
            }
        });
    } catch (error) {
        // If any error occurs, return error response
        res.status(500).json({ message: "Internal server error0" });
        console.log(error);
    }
};


/**
 * Verify user's OTP based on provided information.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} JSON response with OTP verification status and message
 */
module.exports.verifyOTP = async (req, res) => {
    // Extract OTP code from request body
    let { code } = req.body;

    // Extract user ID from request parameters
    const id = req.params.id;

    // Check if user ID is missing in request
    if (!id) {
        return res.status(400).json({ message: "Invalid request" }); // Return error response if user ID is missing
    }

    // Check if OTP code is missing or invalid in request
    if (!code || code.length < 6) {
        return res.status(400).json({message:'Please provide a valid OTP code'}); // Return error response if OTP code is missing or invalid
    }

    try {
        // Retrieve user from database using user ID
        let user = await new userRepository().getUserById(id);

        // Check if user does not exist
        if(!user){
            return res.status(404).json({message:'User not found'}); // Return error response if user does not exist
        }

        // Check if user's account is not active
        if(!user.isActive){
            return res.status(400).json({message:'Your account has been blocked,contact technical support for further details!!'}); // Return error response if user's account is not active
        }

        // Check if user is already verified
        if(user.isVerified){
            return res.status(400).json({message:'User already verified'}); // Return error response if user is already verified
        }

        // Check if OTP has expired
        if (Date.now() > user.otp?.expiresAt) {
            return res.status(400).json({ message: "OTP expired, Please request new code!" }); // Return error response if OTP has expired
        }

        // Compare provided OTP code with stored OTP code
        let otp = await hashData.compareData(code, user.otp.code);

        // Check if OTP code is invalid
        if(!otp){
            return res.status(400).json({message:'Invalid OTP code'}); // Return error response if OTP code is invalid
        }

        // Clear OTP from user's record in database
        user = await new userRepository().clearOtp(id);

        // Return success response if OTP is verified successfully
        return res.status(200).json({message:'OTP verified successfully'});
    } catch (error) {
        console.log(error); // Log error to console for debugging
        res.status(500).json({message:'Internal server error'}) // Return error response if an internal server error occurs
    }
};

module.exports.protect = async (req, res, next) => {

    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    else if(req.cookies?.jwt){
        token = req.cookies.jwt;
    }

    if(!token){
        return  next(res.status(401).json({status:'fail', message:"Unauthorized, Please log in to get access."}));
    }
    try {
        const decoded = await verifyJWT(token, process.env.JWT_SECRET);
        // Check if the JWT has expired   
        if(!decoded){
            return  next(res.status(401).json({status:'fail', message:"Unauthorized, Please log in to get access."}));
        }
        const user = await new userRepository().getUserById(decoded.user);
        // Check if user exists
        if(!user){
            return  next(res.status(401).json({status:'fail', message:"Unauthorized, Please log in to get access."}));
        }

        if (user.changedPasswordAfter(decoded.iat)) { 
            return next(res.status(401).json({status:'fail',message:'User recently changed password! Please log in again.'}))
        }
        const newUser = {
            id: user._id,
            name: user.name,
            email: user.email,
            photo: user?.photo,
        };
        req.user = newUser;
        res.locals.user = newUser;
        next()
    } catch (error) {
        console.log(error);
        res.status(401).json({message:"Internal server error"});
    }
    
// next()
}