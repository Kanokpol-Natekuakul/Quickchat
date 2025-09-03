import jwt from "jsonwebtoken"
import User from "../models/User.js"


export const protect=async(req,res,next)=>{
  let token = req.headers.authorization
  

try {
    if (!token) {
      return res.status(401).json({success: false, message:"No token provided"})
    }

    // รองรับทั้ง "Bearer TOKEN" และ "TOKEN"
    if (token.startsWith('Bearer ')) {
      token = token.slice(7)
    }

    const decode = jwt.verify(token,process.env.JWT_SECRET)
    const userId = decode.id

    const user = await User.findById(userId).select('-password')
    if (!user) {
      return res.status(401).json({success: false, message:"User not found"})
    }
    
    req.user = user
    next()
  } catch (error) {
    console.error('Auth error:', error)
    res.status(401).json({success: false, message:"Invalid token"})
  }
}