import jwt from "jsonwebtoken"
import { tryCatch } from "./tryCatch.js";


export const signJWT = function (data){
    return tryCatch(()=> jwt.sign(data, process.env.JWT_SECRET))
}

export const verifyJWT = function (token){
    return tryCatch(()=> jwt.verify(token, process.env.JWT_SECRET))
}

export const emailValidator = function(v) {
    const regex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return regex.test(v)
}