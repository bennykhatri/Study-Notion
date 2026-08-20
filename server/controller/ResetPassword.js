const User = require("../models/user");
const mailSender = require("../utils/mailSender");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

//Reset Password Token
exports.resetPasswordToken = async (req,res) => 
{
    try
    {
        //Fetch email from
    const email = req.body;

    //Get email from the request
    const user = await User.findOne({email: email});

    //Verify the email if user exists or not
    if(!user)
    {
        return res.status(400).json({
            success: false,
            message: "Your email is not registered"
        })
    }

    //Generate Token
    const token = crypto.randomUUID();
    //Update user by adding token and expiration time
    const updatedDetails = await User.fineOneAndUpdate({email: email}, {token: token, resetPasswordExpires: Date.now() + 5*60*1000}, {new:true});
    //Create URL
    const url = `https://localhost:3000/update-password/${token}`;

    //Send email containing URL
    await mailSender(email, "Password Reset Link", `Password Reset Link: ${url}`);
    //Return Response
    return res.status(200).json({
        success: true,
        message: "Email send successfully"
    })
    }
    catch(error)
    {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while reset password"
        })
    }
}

//Reset Password
exports.resetPassword = async (req, res) => 
{
    try
    {
        //Fetch Data
        const {token, password, confirmPassword} = req.body;

        //Validation
        if(password !== confirmPassword)
        {
            return res.status(401).json({
                success: false,
                message: "Password & Confirm Password are not matching"
            })
        }
        //Get user details from DB using Token
        const userDetails = await User.findOne({token: token});

        //If no entry - invalid token
        if(!userDetails)
        {
            return res.status(400).json({
                success: false,
                message: "Token is invalid"
            })
        }

        //Token time check
        if(userDetails.resetPasswordExpires < Date.now())
        {
            return res.status(400).json({
                success: false,
                message: "Token validity expired! Please regenerate your token"
            })
        }

        //Hash Password
        const hashedPassword = await bcrypt.hash(password, 10);

        //Update Password
        await User.findOneAndUpdate(
            {token: token},
            {password: hashedPassword},
            {new: true},
        )

        //Return Response
        return res.status(200).json({
            success: true,
            message: "Password reset successful",
        })
    }
    catch(error)
    {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while reset password"
        })
    }
}