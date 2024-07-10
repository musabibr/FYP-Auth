const crypto = require('crypto');
const validator = require("validator");
// const multer = require('multer');
const sharp = require("sharp");
const userRepository = require("../Data_layer/repositories/userRepository");
const Email = require('../utils/email')
const { generateJWT  } = require('../middleware/middleware');
const hashData = require('../utils/hashData');
const upload = require('../middleware/multer')
const {cloudinary ,deleteOldImg} = require('../utils/cloudinary');




exports.uploadUserPhoto = upload.single('image');



function validateUser(res,name, email, password) {
    if(!name || !email || !password){
        return res.status(400).json({message:"Missing required fields"});
    }
    if(name.length < 3 || name.length > 30){    
        return res.status(400).json({message:"Name must be between 3 and 30 characters"});
    }
    if(password.length < 8){
        return res.status(400).json({message:"Password must be at least 8 characters"});
    }
    if(!validator.isEmail(email)){
        return res.status(400).json({message:"Invalid email format"});
    }
}


exports.signup = async (req, res, next)=>{
    let { name, email, password } = req.body;

    try {
        validateUser(res, name, email, password);

        let user = await new userRepository().getUser(email);

        if (user) {
            return res.status(401).json({message:"User already exist"});
        }

        password = await hashData.encryptData(password);
        user = await new userRepository().createUser(name, email, password);

        // create and send token
        createSendToken(res,req, user, 'Account created successfully!');
    } catch (error) {
        console.log(error);
        res.status(400).json({ message: error.message });
    }
}

exports.sendGreetingEmail = async (req, res) => {
    const user = req?.user;
    if (!user) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    try {
        // send welcome email 
        const url = `${req.protocol}://${req.get('host')}/api/v1/users/${user._id}/verify`;
        const mail = await new Email(user, url).sendWelcome();
        if (!mail) {
            return res.status(500).json({message:"Email not sent"});
        }
        res.status(200).json({message:"Email sent"});
    } catch (error) {
        console.log(error);
        res.status(400).json({ message: error.message });
    }

}

/**
 * This function is used to handle the login request.
 * It first validates that the email and password are provided and that the password is at least 8 characters long.
 * It then validates that the email is in a valid format.
 * After that, it retrieves the user from the database based on the provided email.
 * If the user does not exist, it returns a 404 error.
 * If the user's password does not match the provided password, it returns a 401 error.
 * If the user's account is not verified, it returns a 401 error.
 * If the user's account is deactivated, it returns a 401 error.
 * If all the above conditions pass, it generates and sends a JWT token to the user.
 * Finally, it returns a success response.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @param {Function} next - The next middleware function
 * @return {Promise<void>} A promise that resolves to void
 */
exports.login = async (req, res,next) => {
    // Extract email and password from the request body
    const { email, password } = req.body;

    // Validate that email and password are provided
    if (!email || !password) {
        return next(res.status(400).json({ status:'failed',message:'Please provide all the required fields.'}))
    }

    // Validate that password is at least 8 characters long
    if(password.length < 8){
        return next(res.status(400).json({status:'failed',message:"Password must be at least 8 characters"}));
    }

    // Validate that email is in a valid format
    if(!validator.isEmail(email)){
        return next(res.status(400).json({status:'failed',message:"Invalid email format"}));
    }

    try {
        // Retrieve user from database based on email
        let user = await new userRepository().getUser(email);

        // If user does not exist, return a 404 error
        if (!user) {
            return next(res.status(404).json({status:'failed',message:'User not found, please signup!'}))
        }
        
        // If user's password does not match the provided password, return a 401 error
        if (!(await hashData.compareData(password, user.password))) {
            return next(res.status(401).json({status:'failed',message:'Invalid email or password!'}))
        }

        // If user's account is not verified, return a 401 error
        if (!user.isVerified) {
            return next(res.status(401).json({status:'failed',message:'Please verify your email to proceed.'}))
        }

        // If user's account is deactivated, return a 401 error
        if(!user.isActive){
            return next(res.status(401).json({status:'failed',message:'Your account has been deactivated'}))
        }

        // Generate and send JWT token to user
        createSendToken(res,req, user, "Login successful");
        // next()
    } catch (error) {
        // If an error occurs, return a 500 error
        res.status(500).json({ message: 'Internal server error' });
        console.log(error);
    }
}


/**
 * This function is used to handle the logout request.
 * It sets the jwt cookie to an empty string, which effectively logs the user out.
 * It also clears the req.user and res.locals.user variables.
 * Finally, it returns a success response.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} - The response object
 */
exports.logout = (req, res) => {
    // Set the jwt cookie to an empty string, effectively logging the user out
    res.clearCookie('jwt', { httpOnly: true });
    // res.cookie("jwt", "", { maxAge: 1, httpOnly: true });

    // Clear the req.user and res.locals.user variables
    delete req.user;
    delete res.locals.user;

    // Return a success response
    return res.status(200).json({ status: 'success', message: 'Logged out successfully' });
}

exports.restrictedTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        next();
    };
}

// This function is used to handle the forgot password request.
// It first validates that an email is provided and it is a valid email format.
// Then it retrieves the user associated with the provided email.
// If the user does not exist, it returns a 404 error.
// If the user is not verified, it returns a 401 error.
// If the user's account is deactivated, it returns a 401 error.
// If all the above conditions pass, it generates a password reset token for the user.
// It then saves the user with the new password reset token and expiration date.
// After that, it creates the reset URL and sends a password reset email to the user.
// If the email sending process fails, it clears the password reset token and expiration date from the user and returns a 500 error.
// If everything succeeds, it returns a 200 response with a success message.
exports.forgotPassword = async (req, res) => {
    // Extract the email from the request body
    const  {email}  = req.body;

    // Validate that the email is provided and it is a valid email format
    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ message: 'Please provide a valid email' });
    }

    // Retrieve the user associated with the provided email
    let user = (await (new userRepository().getUser(email)))
    // If the user does not exist, return a 404 error
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // If the user is not verified, return a 401 error
    if (user.isVerified === false) {
        return res.status(401).json({ message: 'Please verify your email first' });
    }

    // If the user's account is deactivated, return a 401 error
    if (user.isActive === false) {
        return res.status(401).json({ message: 'Account deactivated, contact technical support for further details.' });
    }

    // Generate a password reset token for the user
    user = new userRepository().createPasswordResetToken(user);
    await user.save({ validateBeforeSave: false });

    try {
        // Create the reset URL and send a password reset email to the user
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/reset-password/${user.resetToken}`;
        await new Email(user, resetURL).sendPasswordReset();

        // Return a 200 response with a success message
        res.status(200).json({
            status: 'success',
            message: 'Password reset email sent',
        });
    } catch (error) {
        // If the email sending process fails, clear the password reset token and expiration date from the user and return a 500 error
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        res.status(500).json({ message: error.message });
    }
}

/**
 * This function is responsible for handling the password reset process.
 * 
 * It takes in a request object and a response object, and returns a JSON response.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} - A JSON response containing the status, message, and data.
 */
exports.resetPassword = async (req, res) => {
    // Extract the reset token from the request params
    const resetToken = req.params.resetToken;
    const newPassword = req.body?.password;
    if(!newPassword || newPassword.length<8){
        return res.status(400).json({ message: 'Please provide a valid password' });
    }
    // Validate that the reset token is provided and it is a valid reset token
    if (!resetToken) {
        // If reset token is not provided, return a 400 error with a message
        return res.status(400).json({ message: 'Please provide a valid reset token' });
    }
    
    // Hash the reset token to match the hashed token stored in the user's document
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Retrieve the user based on the hashed reset token
    const user = await new userRepository().getUserByResetToken(hashedToken);
    
    // If the user does not exist, return a 400 error with a message
    if (!user) {
        // If user is not found, return a 400 error with a message
        return res.status(400).json({ message: 'Token is invalid or has expired' });
    }
    
    try {
        // Set the new password and clear the reset token and expiration date 
        user.password = await hashData.encryptData(newPassword);
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        // Save the changes to the user's document
        await user.save();
        // Clear the password reset token and expiration date from the user's document
        user.password = user.passwordResetToken = user.passwordResetExpires = undefined;
        // Send a success response
        res.status(200).json({status:'success',message:'Password reset successfully'});
    } catch (error) {
        // If an error occurs, return a 500 error with a message
        res.status(500).json({ message: 'Something went wrong' });
        console.log(error);
    }
}


exports.updatePassword = async (req, res) => {
    const id = req?.user?.id;
    const { oldPassword, newPassword } = req.body;
    if(!oldPassword || !newPassword){
        return res.status(400).json({status:'failed',message:'Please provide all the required fields.'})
    }
    if(newPassword.length < 8){
        return res.status(400).json({status:'failed',message:"Password must be at least 8 characters"});
    }
    const user = await new userRepository().getUserById(id);
    if (!(await hashData.compareData(oldPassword, user.password))) {
        return res.status(401).json({ status: 'failed', message: 'Invalid password!' });
    }
    try {
        user.password = await hashData(newPassword);
        await user.save({ validateBeforeSave: false });
        createSendToken(res,req, user, 'Password updated successfully!');
        
    } catch (error) {
        res.status(500).json({ message: 'Something went wrong' });
        console.log(error);
    }
}

const createSendToken = async (res, req, user ,message) => {
    // Create a new user object to be returned in the response
    const newUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        photo: user?.photo
    };
        
    // Generate a JWT token with the user's ID and a 30-day expiration date
    const token = generateJWT({user:newUser.id}, process.env.JWT_SECRET, { expiresIn: '30d' });
        
    // Set a cookie with the JWT token and a 30-day expiration date
    res.cookie('jwt', token, {
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        // secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
    });
    req.user = newUser;
    res.locals.user = newUser;
    return res.status(200).json({
        status: 'success',
        message: message,
        data: {
            user: newUser
        },
        // token: token
    });
}

/**
 * This function is used to handle the request to get a user's profile information.
 * It first retrieves the user's ID from the request object.
 * It then calls the userRepository's getUserById method to retrieve the user's information.
 * If the retrieval is successful, it constructs a new user object with the retrieved information.
 * It then returns a success response with the new user information.
 * If there is an error during the retrieval, it returns a 500 error response.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 */
exports.profile = async (req, res) => {
    // Retrieve the user's ID from the request object
    const id = req?.user?.id;

    try {
        // Call the userRepository's getUserById method to retrieve the user's information
        const user = await new userRepository().getUserById(id);

        // Construct a new user object with the retrieved information
        const newUser = {
            id: user._id,
            name: user.name,
            email: user.email,
            photo: user?.photo
        }

        // Return a success response with the new user information
        res.status(200).json({
            status: 'success',
            data: {
                user:newUser
            }
        });
        
    } catch (error) {
        // If there is an error during the retrieval, return a 500 error response
        res.status(500).json({ message: 'Something went wrong' });
        console.log(error);
    }
}

/**
 * This function is used to handle the request to update a user's information.
 * It expects a request object with a user property containing an id property.
 * It also expects a request body containing a name property.
 * It first checks if the name property is present and has a length between 3 and 30 characters.
 * If not, it returns a 400 error response with a message indicating that the name cannot be empty.
 * If the name is valid, it tries to update the user's information using the userRepository's updateUser method.
 * If the update is successful, it constructs a new user object with the updated information.
 * It then returns a success response with the new user information.
 * If there is an error during the update, it returns a 500 error response with a generic message.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 */
exports.updateMe = async (req,res)=>{
    // Extract the name from the request body
    const {name} = req.body;
    // Extract the user id from the request user property
    const id = req?.user?.id;

    // Check if the name is present and has a valid length
    if (!name || (name.length < 3 || name.length > 30)) {
        // If not, return a 400 error response with a message indicating that the name cannot be empty
        return res.status(400).json({ message: 'user name cannot be empty' });
    }

    try {
        // Try to update the user's information using the userRepository's updateUser method
        const user = await new userRepository().updateUser(id, name ); 
        // Construct a new user object with the updated information
        const newUser = {
            id: user._id,
            name: user.name,
            email: user.email,
            photo: user?.photo
        }
        // Return a success response with the new user information
        res.status(200).json({
            status: 'success',
            data: {
                newUser
            }
        });
        
    } catch (error) {
        // If there is an error during the update, return a 500 error response with a generic message
        res.status(500).json({ message: 'Something went wrong' });
        console.log(error);
    }
}

/**
 * This function is used to handle the request to update a user's photo.
 * It first checks if a file was uploaded in the request.
 * If not, it returns a 400 error response.
 * If a file was uploaded, it generates a filename for the user's photo.
 * It then uploads the photo to the cloudinary server using the cloudinary library.
 * The uploaded photo's filename is set to the generated filename.
 * If the upload fails, it returns a 500 error response.
 * It then retrieves the URL of the uploaded photo from cloudinary.
 * It calls the userRepository's uploadUserPhoto method to update the user's photo.
 * It constructs a new user object with the updated information.
 * It returns a success response with the updated user information and the upload results from cloudinary.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 */
exports.updatePhoto = async (req, res) => {
    // Retrieve the user's ID from the request
    const id = req?.user?.id;
    
    // Check if a file was uploaded in the request
    if (!req.file) {
        // If not, return a 400 error response
        return res.status(400).json({ message: 'Please upload a photo' });
    }

    try {
        // Generate a filename for the user's photo
        req.file.filename = `user-${req.user.id}-${Date.now()}`;
        let imgPId = req.file.filename || null
        let user = await new userRepository().getUserById(id);
        
        // Upload the photo to the cloudinary server
        const results = await cloudinary.uploader.upload(
            req.file.path,
            {
                public_id: req.file.filename,
                }
            ); 
                
        // Check if the upload failed
        if(!results){
            // If so, return a 500 error response
            return res.status(500).json({ message: 'Image upload failed' });
        }

        // Retrieve the URL of the uploaded photo from cloudinary
        const photo = cloudinary.url(`${req.file.filename} `, {
            fetch_format: 'jpeg',
            quality: 'auto',
            crop: 'auto',
            gravity: 'auto',
            width: 500,
            height:500,
        });

        // Delete the old photo from cloudinary  
        if (user?.imgPId) {
            await deleteOldImg(user?.imgPId);
        }


        // Update the user's photo in the database
        user = await new userRepository().uploadUserPhoto(id,photo,imgPId);

        // Construct a new user object with the updated information
        const newUser = {
            id: user._id,
            name: user.name,
            email: user.email,
            photo: user?.photo
        }

        // Return a success response with the updated user information and the upload results from cloudinary
        res.status(200).json({
            status: 'success',
            data: {
                user: newUser,
                // uploadResults: results,
            }
        });

    } catch (error) {
        // If an error occurs, return a 500 error response
        res.status(500).json({ message: 'Something went wrong' });
        console.log(error);
    }
}
/**
 * This function is used to handle the request to delete a user's account.
 * It first retrieves the user from the request.
 * Then it calls the userRepository's DeactivateAccount method to deactivate the user's account.
 * After that, it clears the req.user and res.locals.user variables.
 * It also clears the jwt cookie.
 * Finally, it returns a success response.
 *
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {Object} - The response object
 */
exports.deleteMe = async (req, res) => {
    try {

        // Retrieve the user from the request
        const user = req.user;
        if(!user){
            return res.status(401).json({status:'fail',message:'Unauthorized, Please log in to get access.'});
        }
        if((await new userRepository().getUserById(user.id))?.isActive === false){
            return res.status(401).json({status:'fail',message:'Unauthorized, Please log in to get access.'});
            
        }
        // Call the userRepository's DeactivateAccount method to deactivate the user's account
        await new userRepository().DeactivateAccount(user.id);
        // Clear the req.user and res.locals.user variables
        req.user = undefined;
        res.locals.user = undefined;
        // Clear the jwt cookie
        res.clearCookie('jwt', { httpOnly: true });
        // Return a success response
        return res.status(204).json({ status: 'success', data: null });

    } catch (error) {
        // If an error occurs, return an error response
        res.status(500).json('Internal server error');
        console.log(error);
    }
}
