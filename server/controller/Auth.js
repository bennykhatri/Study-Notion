const User = require("../models/user");
const OTP = rquire("../models/otp");
const otpGenerator = require("otp-generator");
const Profile = require("../models/profile");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
require("dotenv").config();

//Send OTP
exports.sendOTP = async (req, res) => {
    try
    {
    //Fetch email from request body
    const {email} = req.body;

    //Check if user already present
    const checkUserPresent = await User.findOne({email});

    //If user alrady exists, then return a response
    if(checkUserPresent)
    {
        return res.status(401).json({
            success: false,
            message: "User alread exists"
        })
    }

    //Generate OTP
        let otp = otpGenerator.generate(6, {upperCaseAlphabets:false, lowerCaseAlphabets:false,specialChars:false});
        console.log("Otp Generated", otp);

    //Check if OTP is unique or not
    const result = await OTP.findOne({otp: otp});

    //Generating a new OTP and comparing again
    while(result)
    {
        otp = otpGenerator.generate(6, {upperCaseAlphabets:false, lowerCaseAlphabets:false,specialChars:false});
        result = await OTP.findOne({otp: otp});
    }

    //Creating OTP payload for saving it into the database
    const otpPayload = {email,otp};

    //Creating an entry into DB
    const otpBody = await OTP.create(otpPayload);
    console.log(otpBody);

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
                role: user.role
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
    //Get Data from req body
    //Get Old Password, New password & Confirm new password
    //Validation

    //Update the password in DB
    //Send Mail - Password Updated  
    //Return response
}