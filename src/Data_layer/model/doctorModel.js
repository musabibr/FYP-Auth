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
        state:{
            type: String,
            required: true
        },
        city: {
            type: String,
            required:true
        },
    },
    availability: {
        type: [
            {
                day: {
                    type: String,
                    enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                    required: true
                },
                startTime: {
                    type: String,
                    required: true
                },
                endTime: {
                    type: String,
                    required: true
                }
            }
        ]
    },
    isAvailable: {
        type: Boolean,
        default: false,
        set: function(val) {
            const now = new Date();
            const day = now.getDay();
            const hour = now.getHours();
            const minutes = now.getMinutes();
            const availability = this.availability.find(availability => availability.day === day);
            if (availability) {
                const startHour = parseInt(availability.startTime.split(":")[0], 10);
                const startMinutes = parseInt(availability.startTime.split(":")[1], 10);
                const endHour = parseInt(availability.endTime.split(":")[0], 10);
                const endMinutes = parseInt(availability.endTime.split(":")[1], 10);
                if (hour >= startHour && hour < endHour) {
                    if (startMinutes <= minutes && minutes < endMinutes) {
                        return true;
                    }
                }
            }
            return false;
        }
    },
    accountStatus: {
        enum: ['pending', 'approved', 'rejected'],
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