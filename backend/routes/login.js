import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Joi from "joi";
import LoginModel from "../models/login.js";

const loginRouter = express.Router();
const isProduction = process.env.NODE_ENV === "production";



// Helper function to generate JWT token
const generateToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1d" });



// Input validation schemas
const authSchema = Joi.object({
  name: Joi.string().min(3).optional(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});



// Login Route
loginRouter.post("/login", async (req, res) => {
  try {
    const { error } = authSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = req.body;
    const user = await LoginModel.findOne({ email });
    if (!user) return res.status(401).json({ message: "User not found." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect password." });

    const token = generateToken(user._id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "Strict",
    });

    return res.status(200).json({
      message: "Login successful!",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});




// Signup Route
loginRouter.post("/signup", async (req, res) => {
  try {
    const { error } = authSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { name, email, password } = req.body;

    const existingUser = await LoginModel.findOne({ email });
    if (existingUser) return res.status(409).json({ message: "Email already registered." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new LoginModel({ name, email, password: hashedPassword });
    await newUser.save();

    const token = generateToken(newUser._id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "Strict",
    });

    return res.status(201).json({
      message: "Signup successful!",
      user: { id: newUser._id, name: newUser.name, email: newUser.email },
      token,
    });
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});




// Logout Route
loginRouter.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.status(200).json({ message: "Logout successful." });
});





export default loginRouter;
