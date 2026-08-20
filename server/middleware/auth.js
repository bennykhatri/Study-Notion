const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/user");

//Auth
exports.auth = async(req,res,next) =>
{
    try
    {
        //Extract the token
        const token = req.cookies.token || req.body.token || req.header("Authorisation").replace("Bearer", "");

        //If token in missing
        if(!token)
        {
            return res.status(401).json({
                success: false,
                message: "Token is missing",
            })
        }

        try
        {
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode;
        }
        catch(error)
        {
            //Verification Failed
            return res.status(401).json({
                success: false,
                message: "Token is invalid",
            })
        }
        next();
    }
    catch(error)
    {
        return res.status(401).json({
            success: false,
            message: "Something went wrong while validating the token"
        })
    }
}
//isStudent
exports.isStudent = async (req,res, next) => 
{
    try
    {
        if(req.user.accountType !== "Student")
        {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for students only",
            })
        }
        next();
    }
    catch(error)
    {
        res.status(500).json({
            success: false,
            message: "User role can't be verified, please try again"
        })
    }
} 

//isInstructor
exports.isInstructor = async (req,res, next) => 
{
    try
    {
        if(req.user.accountType !== "Instructor")
        {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for instructor only",
            })
        }
        next();
    }
    catch(error)
    {
        res.status(500).json({
            success: false,
            message: "User role can't be verified, please try again"
        })
    }
} 

//isAdmin
exports.isAdmin = async (req,res, next) => 
{
    try
    {
        if(req.user.accountType !== "Admin")
        {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for admin only",
            })
        }
        next();
    }
    catch(error)
    {
        res.status(500).json({
            success: false,
            message: "User role can't be verified, please try again"
        })
    }
} 