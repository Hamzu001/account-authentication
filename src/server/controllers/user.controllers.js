import { User } from "../models/user.models.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { asyncHandler } from "../utils/asyncHandler.js"
import { sendOtpToEmail } from "../utils/sendOtptoMail.js"
import { signJWT, verifyJWT } from "../utils/functions.js"
import { asyncTryCatch } from "../utils/tryCatch.js"
import bcrypt from "bcrypt"

const log = console.log

// register user
const registerUser = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body

  if ([email, userName, password].some((field) => field?.trim() === "")) {
    // throw new ApiError(400,"All fields are required")
    res.status(400).send({ msg: "All fields are required" })
  }

  if (password.length < 8) {
    res.status(401).send({ error: "password aleast 8 characters" })
  }

  const isUserExist = await User.findOne({ email })

  if (isUserExist) {
    throw new ApiError(401, "User with email already exist ")
  }

  const user = await User.create({
    userName: userName.toLowerCase(),
    email,
    password,
  })

  const { data: generateToken } = signJWT({ id: user._id })
  // log({"token" : generateToken})

  asyncTryCatch(() => sendOtpToEmail(email, generateToken))

  const createdUser = await User.findById(user._id).select("-password")

  return res
    .status(200)
    .json(
      new ApiResponse(200, { "Created user": createdUser }, "user is register")
    )
})

// token varification
const verifyToken = asyncHandler(async (req, res) => {
  const { token } = req.query

  if (!token) {
    // throw new ApiError(500, "provide token")
    res.status(400).json({ msg: "provide token " })
  }

  const { data: decodedToken } = verifyJWT(token)
  if (!decodedToken) {
    res.status(400).send({ msg: "provide correct token" })
    res.redirect(302, "/message?value=InvalidToken")
    // throw new ApiError(400, "provide correct token")
  }

  const user = await User.findByIdAndUpdate(
    decodedToken.id,
    {
      $set: { isVerified: true },
    },
    { new: true }
  ).select("-password")

  if (!user) {
    throw new ApiError(400, "user does not exist")
  }

  const { data: generateToken } = signJWT({ id: user._id })

  //   res.status(200).send(new ApiResponse(200, user, "email verified user"))
  res.cookie("token", generateToken, { httpOnly: true, secure: true })
  res.redirect(302, "/home")
})

// user login
const userLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body
  // log(email,password)

  if ([email, password].some((field) => field?.trim() === "")) {
    // throw new ApiError(400,"All fields are required")
    res.status(400).send({ msg: "All fields are required" })
  }

  const user = await User.findOne({ email })
  if (!user) {
    res.status(400).send({ msg: "user does not exist" })
  }

  const isPasswordCompare = await bcrypt.compare(password, user.password)

  if (!isPasswordCompare) {
    res.status(401).send({ msg: "Invalid user credentials" })
  }

  const { data: generateAccessToken } = signJWT({ id: user._id })

  res
    .status(200)
    .json(new ApiResponse(200, generateAccessToken, "user login sucessfully"))
})

// getuser
const getCurrentUser = asyncHandler(async (req, res) => {
  const { token } = req.cookies

  if (!token) {
    res.status(400).json({ msg: "no token provided" })
  }

  const { data: verifyToken } = verifyJWT(token)

  if (!verifyToken) {
    res.status(400).json({ msg: "provided token is invalid" })
  }

  const user = await User.findById(verifyToken.id).select("-password")
  res.send(user)
})

export { registerUser, verifyToken, userLogin, getCurrentUser }
