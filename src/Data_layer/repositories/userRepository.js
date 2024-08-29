const User = require("../model/userModel");
const crypto = require("crypto");

class UserRepository {
    async getUser(email) {
        let user = await User.findOne({email});
        // return  users.find((user) => user.email === email);
        return user;
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

    async createUser(name, email, password,gender) {
        return await User.create({ name, email, password,gender });
    }

    async updateUser(id, name) {
        const user = await this.getUserById(id);
        user.name = name || user.name;
        await user.save();
        return user
    }
    async uploadUserPhoto(id, photo,imgPId) {
        const user = await this.getUserById(id);
        user.photo = photo || 'default.jpeg';
        user.imgPId = imgPId || null;
        await user.save();
        return user
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
    createPasswordResetToken(user) {
        const resetToken = crypto.randomBytes(32).toString("hex");

            user.passwordResetToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        user.passwordResetExpires = Date.now() + 10 * 60 * 1000;
        user.resetToken = resetToken;
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

//  