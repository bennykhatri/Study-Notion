const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
   email: {
    type: String,
    required: true,
   },
   otp: {
    type: Number,
    required: true,
   },
   createdAt: {
    type: Date,
    default: Date.now,
    expires: 5*60
   }
})

//Function to send email

async function sendVerificationEmail(email, otp)
{
    try
    {
        const mailResponse = await mailSender(email, "Verification Email from Benny Khatri", otp);
        console.log("Email sent succesfully", mailResponse);
    }
    catch(error)
    {
        console.log("Error occured while sending the email", email);
        throw error;
    }
}

otpSchema.pre("save", async function(next){
    await sendVerificationEmail(this.email, this.otp);
    next();
})

module.exports = mongoose.model("OTP", otpSchema);