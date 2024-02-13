import otpGenerator from "otp-generator"

const OTP = otpGenerator.generate(6, {
  upperCaseAlphabets: false,
  specialChars: false
})

export default OTP

