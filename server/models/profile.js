const mongoose = require("mongoose");

const ProfileSchema = new mongoose.Schema({
    gender: {
        type: String,
        required: true,
    },
    dateOfBirth: {
        type: String
    },
    about: {
        type: String,
        trim: true
    },
    contactNumber: {
        type: String,
        trim: true
    }
})

module.exports = mongoose.model("Profile", ProfileSchema);