import jwt from "jsonwebtoken"
import User from "../models/user.model"

export const protectRoute = async (req, res, next) =>{
    try {
        const token = req.cookie.jwt

        if (!token) {
            return res.status(401).json({message: "Unauthorized - No token provided"})
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        if (!decoded) {
            return res.status(401).json({message: "Unauthorized - No token provided"})
        }

        const user = await User.findById(decoded.userId).select("-password")

        if (!user) {
            return res.status(404).json({message: "User Not found"})
        }

        req.user = user

        next()

    } catch (error) {
        console.log("Errors in protected route middle ware", error.message);
        res.status(500).json({message: "Internal server error"})
    }
}
