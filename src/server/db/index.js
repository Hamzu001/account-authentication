import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const mongodbUri = process.env.MONGODB_URI + "/" + DB_NAME
const db = mongoose.connection


mongoose.connect(mongodbUri)

const log = console.log

db.on("connected", () => log("connected to mongodb"));
db.on("open", () => log("connected to database"));
db.on("disconnected", () => log("disconnected to mongodb database"));
db.on("reconnected", () => log("reconnected to mongodb database"));
db.on("disconnecting", () => log("disconnecting to mongodb database"));
db.on("error", (err) => console.error(err));
db.on("close", () => log("connection close"));
