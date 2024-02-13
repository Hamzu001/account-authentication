import nodemailer from "nodemailer"
// import { ApiError } from "./ApiError.js"

async function sendOtpToEmail(reseverEmail, token) {
  let transporter = nodemailer.createTransport({
    service: "gmail",
    port: 465,
    secure: true,
    logger: true,
    debug: true,
    secureConnection: false,
    auth: {
      user: process.env.AUTH_MAIL,
      pass: process.env.AUTH_PASSWORD
    },
    tls: {
      rejectUnauthorized: true
    }
  })

  let mailOptions = {
    from: process.env.AUTH_MAIL,
    to: reseverEmail,
    subject: "Quiz App: Verify your email",
    html: `<h2 style="color:black;text-align:center;">Quiz App send you email for otp varification<br>Your OTP is here <br> <b> <a href="${process.env.WEB_URL}/api/v1/user/verify?token=` + token +`">Link Here</a>  </b> </h2>`
  }
  
  // send otp to email
  transporter.sendMail(mailOptions, async function (error, info) {
    if (error) {
      console.log({ error })
      
      // throw new ApiError(500, "send otp to email error")
    } else {
      console.log(info.response)
    }
  })
}

export { sendOtpToEmail }





