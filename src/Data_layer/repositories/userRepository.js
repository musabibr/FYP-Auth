const User = require("../model/userModel");
const validator = require("validator");

class UserRepository {
    async getUser(email) {
        this.validateEmail(email);
        return await User.findOne({ email });
    }

    async getUserById(id) {
        const user = await User.findById(id);
        return user;
    }
    async getUserByResetToken(hashedToken) {
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() },
        });
        return user;
    }

    async createUser(name, email, password) {
        this.validateUser(name, email, password);
        return await User.create({ name, email, password });
    }

    async updateUser(id, name, photo) {
        const user = await this.getUserById(id);
        user.name = name;
        user.photo = photo;
        await user.save();
        return user
    }


    validateEmail(email) {
        if (!validator.isEmail(email)) {
        throw new Error("Invalid email format");
        }
    }

    validateUser(name, email, password) {
        if (!name || !email || !password) {
        throw new Error("Missing required fields");
        }
        this.validateEmail(email);
        if (name.length < 3 || name.length > 30) {
        throw new Error("Name must be between 3 and 30 characters");
        }
        if (password.length < 8) {
        throw new Error("Password must be at least 8 characters");
        }
    }
    async updateOtp(id, otp) {
        const user = await this.getUserById(id);
        const attempts = user.otp?.attempts || 0;
        user.otp = {
        code: otp.code,
        expiresAt: otp.expiresAt,
        attempts: attempts + 1
        };
        await user.save();
        return user;
        }
        
    async clearOtp(id) {    
        const user = await this.getUserById(id);
        user.isVerified = true;
        user.otp = null;
        await user.save();
        return user;
    }

    async deleteUser(id) {
        return User.deleteOne({ _id: id });
    }
    
    async DeactivateAccount(id) {
        const user = await this.getUserById(id);
        user.isActive = false;
        await user.save();
        return user;
    }
}

module.exports = UserRepository;
