const userRepository = require("../Data_layer/repositories/userRepository");
const validator = require("validator");
const Email = require('../utils/email')
const { generateJWT, verifyJWT } = require('../middleware/middleware');
const hashData = require('../utils/hashData');




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
        const token = await generateJWT({user:user._id}, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('jwt', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

        user.password = user.role = user.__v = user.otp = undefined;
        req.user = user;
        // send response
        res.status(201).json({ 
            status: 'success', 
            data: {
                user: user
            },
            token:token
        });
    } catch (error) {
        console.log(error);
        res.status(400).json({ message: error.message });
    }
}

module.exports.sendGreetingEmail = async (req, res) => {
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