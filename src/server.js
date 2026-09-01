import { createServer } from "node:http"
import { createHandler } from "./app.js"
import { JsonStore } from "./store.js"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const store = new JsonStore(process.env.STATE_FILE ?? "./data/state.json")
await store.load()

const server = createServer(createHandler({
  store,
  apiKey: process.env.STATE_API_KEY,
  publicBaseUrl: process.env.PUBLIC_BASE_URL,
}))

server.listen(port, "0.0.0.0", () => {
  console.log(`Executor state handler listening on port ${port}`)
})
