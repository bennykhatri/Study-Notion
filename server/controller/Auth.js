const User = require("../models/user");
const OTP = rquire("../models/otp");
const crypto = require("crypto");
const Profile = require("../models/profile");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
require("dotenv").config();

//Send OTP
exports.sendOTP = async (req, res) => {
    try
    {
    // 1. Fetch email from request body
    const {email} = req.body;

    if(!email)
    {
        return res.status(400).json({
            success: false,
            message: "Email Field is required"
        })
    }

    // 2. Check if the user already exists in the system
    const userExists = await User.findOne({email});

    if(userExists)
    {
        return res.status(409).json({
            success: false,
            message: "User already exists with this email address."
        })
    }

    // 3. Generate a secure 6-digit OTP using native crypto
    let generatedOtp = crypto.randomInt(100000, 999999).toString();
    console.log("Otp Generated", generatedOtp);

    await OTP.findOneAndUpdate(
            { email }, 
            { otp: generatedOtp, createdAt: Date.now() }, 
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

    //Return Successful Status
    res.status(200).json({
        success: true,
        message: "OTP sent successfully",
        otp
    })
    }
    catch(error)
    {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: error.message,
        })
    }

}

//SignUP
exports.signUp = async (req, res) =>
{
    try
    {
        //Fetch data from request body
        const {firstName,lastName,email,password,confirmPassword,accountType,contactNumber,otp} = req.body;

        //Validate Data
        if(!firstName || !lastName || !email || !password || !confirmPassword || !accountType || !contactNumber || !otp)
        {
            return res.status(403).json({
                success: false,
                message: "All fields are required"
            })
        }
        
        //Match both passwords are same
        if(password !== confirmPassword)
        {
            return res.status(400).json({
                success: false,
                message: "Password and Confirm Password are not matching, please try again"
            });
        }

        //Check if user already exists
        const existingUser = await User.findOne({email});
        if(existingUser)
        {
            return res.status(400).json({
                success: false,
                message: "User is already registered"
            })
        }

        //Find most recent OTP for the user
        const recentOTP = await OTP.find({email}).sort({createadAt: -1}).limit(1);
        console.log(recentOTP);

        //Validate OTP
        if(recentOTP.length === 0)
        {
            //OTP not found
            return res.status(400).json({
                success: false,
                message: "OTP not Found"
            })
        } else if(otp !== recentOTP.otp)
        {
            //Invalid OTP
            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            })
        }

        //Hash Password
        const hashedPassword = await bcrypt.hash(password, 10);

        //Create user entry in database
        const profileDetails = await Profile.create({
            gender: null,
            dateOfBirth: null,
            about: null,
            contactNumber: null
        })
        const user = await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password: hashedPassword,
            accountType,
            additionalDetails: profileDetails._id,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
        })

        return res.status(200).json({
            success: true,
            message: "User is registered successfully",
            user
        })
    }
    catch(error)
    {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "User can't be registered. Please try again",
        })
    }
}
//Login
exports.login = async (req,res) =>
{
    try
    {
        //Get data from request body
        const {email,password} = req.body
        //Data Validation
        if(!email || !password )
        {
            return res.status(403).json({
                success: false,
                message: "All fields are required"
            })
        }

        //Check User Exist
        const user = await User.findOne({email}).populate("additionalDetails");
        if(!user)
        {
            return res.status(401).json({
                success: false,
                message: "User is not registered please signup first"
            })
        }
        //Password Matching and JWT Token Generation
        if(await bcrypt.compare(password, user.password))
        { 
            const payload = {
                email: user.email,
                id: user._id,
                accountType: user.accountType
            }
            const token = jwt.sign(payload,process.env.JWT_SECRET,{expiresIn: "2h"})
            user.token = token;
            user.password = undefined;

        const options = {
            expires: new Date(Date.now() + 3*34*60*1000),
            httpOnly: true
        }
        //Create Cookie and Send Response
        res.cookie("token", token, options).status(200).json({
            success: true,
            token,
            user,
            message: "Logged Successfully"
        })
    }
    else
    {
        return res.status(401).json({
            success: false,
            message: "Password is incorrect"
        })
    }
    }
    catch(error)
    {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Login failure! Please try again"
        })
    }
}

//Change Password
exports.changePassword = async(req, res) =>
{
    try{
    //Get Data from req body
    const {email, oldPassword, password, confirmPassword} = req.body;

    //Validate if we have some values for password and confirmPassword
    if(!password || !oldPassword || !email || !confirmPassword)
    {
        return res.status(400).json({
            success: false,
            message: "All fields are required"
        })
    }

    if(password !== confirmPassword)
    {
        return res.status(400).json({
            success: false,
            message: "The new password and confirm password doesn't match"
        })
    }

    //Fetch User from DB
    let user = await User.findOne({email});

    if(!user)
    {
        return res.status(404).json({
            success: false,
            message: "The user doesn't exists"
        })
    }

    //Securely checking the old password using bcrypt
    const isPasswordMatch = await bcrypt.compare(oldPassword, user.password)
    if(!passwordMatch)
    {
        return res.status(401).json({
            success: false,
            message: "The current fields doesn't match"
        })
    }
    
    // 6. Prevent reuse of the exact same password
    const isSameAsOld = await bcrypt.compare(password, user.password)
    if(isSameAsOld)
    {
        return res.status(400).json({
            success: false,
            message: "The new password can't be the same as old password"
        })
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password,saltRounds);

    user.password = hashedPassword;
    await User.save();
    
    //Send Mail - Password Updated
    try
    {
        const mailResponse = await mailSender(user.email, `Password has been updated for ${updatedUser.firstName} ${updatedUser.lastName}`);
        console.log("Email sent succesfully", mailResponse);
    }
    catch(mailError)
    {
        console.log("Error occured while sending the email", user.email, mailError.message);
        throw mailError;
    }

    //Return response
    return res.status(200).json({
        success: true,
        message: "Password Updated Successfully"
    })
    }
    catch (error) {
        // Global catch prevents the server from crashing on unexpected errors
        console.error("Global controller error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error occurred while resetting password"
        });
    }
}