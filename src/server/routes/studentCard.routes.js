import { Router } from "express";
import { studentCard } from "../controllers/studentCard.controllers.js"

const router = Router()

router.route("/student-card").post(studentCard)

export default router;