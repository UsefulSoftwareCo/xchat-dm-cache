import { createServer } from "node:http"
import { dirname, resolve } from "node:path"
import { createHandler } from "./app.js"
import { JsonStore } from "./store.js"
import { XChatDecryptor } from "./xchat.js"
import { XChatCache } from "./xchat-cache.js"
import { createChat } from "@xdevplatform/chat-xdk"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const stateFile = process.env.STATE_FILE ?? "./data/state.json"
const store = new JsonStore(stateFile)
await store.load()
const xchat = new XChatDecryptor({ createChat, pin: process.env.XCHAT_PIN })
const xchatCache = await XChatCache.open({
  filePath: process.env.XCHAT_CACHE_FILE ?? resolve(dirname(stateFile), "xchat-cache.sqlite"),
  decryptor: xchat,
  encryptionSecret: process.env.STATE_API_KEY,
})

const server = createServer(createHandler({
  store,
  apiKey: process.env.STATE_API_KEY,
  publicBaseUrl: process.env.PUBLIC_BASE_URL,
  xchat,
  xchatCache,
  webhookSecret: process.env.X_WEBHOOK_CONSUMER_SECRET,
}))

server.listen(port, "0.0.0.0", () => {
  console.log(`Executor state handler listening on port ${port}`)
  void xchatCache.processPending({ limit: 1000 }).catch((error) => {
    console.error("XChat startup processing failed", error)
  })
})
