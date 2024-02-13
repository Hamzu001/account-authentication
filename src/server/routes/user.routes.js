import { Router } from "express"
import { getCurrentUser, registerUser,  userLogin,  verifyToken } from "../controllers/user.controllers.js";

const router = Router();

router.route("/register").post(registerUser)
router.route("/verify").get(verifyToken)
router.route("/login").post(userLogin)

router.route("/getcurrentuser").get(getCurrentUser)


export default router