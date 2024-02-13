import mongoose, { Schema } from "mongoose"

const studentCardSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },

    fatherName: {
      type: String,
      required: true,
    },

    joinDate: {
      type: String,
      required: true,
    },

    phoneNumber: {
      type: String,
      required: true,
    },

    rollNo: {
      type: String,
      required: true,
    },

    department: {
      type: String,
      required: true,
    },

    session: {
      type: String,
      required: true,
    },

    photo: {
      type: String,
      required: true,
    },

    date: {
      type: Date,
      default: Date.now,
    },

    user: {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
)

export const Card = mongoose.model("Card", studentCardSchema)
