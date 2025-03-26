import jwt from 'jsonwebtoken';

const jwtAuth = (req, res, next) => {
    try {
        if (!req.cookies || !req.cookies.token) {
            return res.status(401).json({ message: "Unauthorized: No token provided" });
        }
        console.log("token : ", req.cookies.token)
        const payload = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
        req.userId = payload.userId;
        next();
    } catch (error) {
        console.error("Unauthorized: ", error.message);
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Unauthorized: Token has expired" });
        }
        return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }
}

export default jwtAuth;