import mongoose, { Schema } from "mongoose";
import { emailValidator } from "../utils/functions.js";
import bcrypt from "bcrypt"

const userSchema = new Schema(
  {
    userName: {
       type: String,
       required: true,
       lowercase: true,
       trim: true
    },

    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        lowercase: true,
        trim: true,
        validate: [ emailValidator , "Please fill a valid email address" ]
    },

    password: {
        type: String,
        required: [true, "password is required"]
    },

    isVerified: {
      type: Boolean,
      default: false
    }
    
  },

  { timestamps: true }

);

userSchema.pre("save", async function (next) {
  if(!this.isModified("password")) return next()

  this.password = await bcrypt.hash(this.password, 10)
  next()
})



export const User = mongoose.model("User", userSchema);
