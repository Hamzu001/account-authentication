import "dotenv/config.js"
import "./ensureEnv.js"
import ViteExpress from "vite-express"
import "./db/index.js"
import app from "./app.js"

const PORT = process.env.PORT || 5000

ViteExpress.listen(app, PORT, () => {
  console.log("Server is runing on port", PORT)
})
