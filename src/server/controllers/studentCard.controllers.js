import { asyncHandler } from "../utils/asyncHandler.js"

const studentCard = asyncHandler(async (req, res) => {
  res.send("student card register")
})

export { studentCard }
