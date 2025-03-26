import express from "express";
import cors from "cors";
import dotenv from "dotenv"
dotenv.config();
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import loginRouter from "./routes/login.js";
import InventoryRouter from "./routes/inventory.js";
const app = express();

// CORS configuration for frontend
app.use(cors({
    origin: [
        "http://localhost:5173"
    ], 
    credentials: true, // Allow credentials (cookies)
}))

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/api", loginRouter);
app.use("/inventory",InventoryRouter);

connectDB();

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});