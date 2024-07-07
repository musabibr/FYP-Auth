const mongoose = require('mongoose');
const validator = require('validator');
const crypto = require("crypto");
const { string } = require('joi');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
        // validate: [validator.isAlpha, 'Please provide a valid name']
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        validate: [validator.isEmail, 'Please provide a valid email']   
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    isVerified: {
        type: Boolean,
        default:false
    },
    role: {
    type: String,
    enum: ['user', 'doctor', 'admin'],
    default: 'user'
    },
    isActive: {
        type: Boolean,
        default:true
    },
    otp: {
        code: String,
        createdAt: Date,
        expiresAt: Date,
        attempts: {
            type: Number,
            default: 0 , 
        }
    },
    photo: {
        type: String,
        default: 'https://res.cloudinary.com/dyhmzdsc9/image/upload/v1720371741/aheeihmowdsxqvtionkd.png'
    },
    imgPId: {
        type: String,
        default: null
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
}, {
    toJSON:true,
    toObject:true
});

userSchema.pre("save", function (next) {
    if (!this.isModified("password") || this.isNew) return next();

    this.passwordChangedAt = Date.now() - 1000;
    next();
});

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(
        this.passwordChangedAt.getTime() / 1000,
        10
        );

        return JWTTimestamp < changedTimestamp;
    }
    // False means NOT changed
    return false;
};

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString("hex");

    this.passwordResetToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

    return resetToken;
};


const User = mongoose.model('User', userSchema);
module.exports = User