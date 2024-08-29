const { required, ref } = require('joi');
const mongoose = require('mongoose');

const doctorSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique:true
    },
    workEmail: {
        type: String,
        required: true,
        unique:true,
    },
    license: {
        type: String,
        required: true
    },
    specialization: {
        type: String,
        required: true
    },
    companyName: {
        type: String,
        required: true
    },
    jobTitle: {
        type: String,
        required:true
    },
    address: {
        address: {
            type: String,
            required: true,
        },
        country: {
            type: String,
            required:true
        },
        city: {
            type: String,
            required:true
        },
    },
    accountStatus: {
        enum: ['pending', 'accepted', 'rejected'],
        default:'pending'
    },
    isApproved: {
        type: Boolean,
        default:false
    }
}, {
    toJSON:true,
    toObject:true
})

doctorSchema.pre(/find^/,async function (next) {
    await this.populate('user').select('name role photo gender');
    next();
})

const Doctor = mongoose.model('Doctor', doctorSchema);
module.exports = Doctor;