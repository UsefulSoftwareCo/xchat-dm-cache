import { createServer } from "node:http"
import { dirname, resolve } from "node:path"
import { createHandler } from "./app.js"
import { JsonStore } from "./store.js"
import { XChatDecryptor } from "./xchat.js"
import { XChatCache } from "./xchat-cache.js"
import { XChatApi } from "./xchat-api.js"
import { XChatSync } from "./xchat-sync.js"
import { createChat } from "@xdevplatform/chat-xdk"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const stateFile = process.env.STATE_FILE ?? "./data/state.json"
const store = new JsonStore(stateFile)
await store.load()
const xchatApi = new XChatApi({
  accessToken: process.env.X_OAUTH2_ACCESS_TOKEN,
  refreshToken: process.env.X_OAUTH2_REFRESH_TOKEN,
  clientId: process.env.X_OAUTH2_CLIENT_ID,
  clientSecret: process.env.X_OAUTH2_CLIENT_SECRET,
})
let xchatCache
const xchat = new XChatDecryptor({
  createChat,
  pin: process.env.XCHAT_PIN,
  diagnostic: (event, fields) => console.log(JSON.stringify({ component: "xchat_decryptor", event, ...fields })),
  refreshIdentity: async ({ userId, publicKeyVersion }) => {
    const refreshed = await xchatApi.getIdentity(userId, publicKeyVersion)
    xchatCache.configure(refreshed)
    return refreshed.identity
  },
})
xchatCache = await XChatCache.open({
  filePath: process.env.XCHAT_CACHE_FILE ?? resolve(dirname(stateFile), "xchat-cache.sqlite"),
  decryptor: xchat,
  encryptionSecret: process.env.XCHAT_CACHE_ENCRYPTION_KEY,
  previousEncryptionSecret: process.env.STATE_API_KEY,
})
xchatApi.setTokenStore({
  get: () => xchatCache.getEncryptedConfig("x_oauth_tokens"),
  set: (tokens) => xchatCache.setEncryptedConfig("x_oauth_tokens", tokens),
})
xchatCache.setSigningKeyProvider(xchatApi.configured ? (userId) => xchatApi.getSigningKeys(userId) : undefined)
const xchatSync = new XChatSync({ api: xchatApi, cache: xchatCache })

const server = createServer(createHandler({
  store,
  apiKey: process.env.STATE_API_KEY,
  publicBaseUrl: process.env.PUBLIC_BASE_URL,
  xchat,
  xchatCache,
  xchatSync,
  webhookSecret: process.env.X_WEBHOOK_CONSUMER_SECRET,
}))

server.listen(port, "0.0.0.0", () => {
  console.log(`Executor state handler listening on port ${port}`)
  void xchatCache.processPending({ limit: 1000 }).catch((error) => {
    console.error("XChat startup processing failed", error)
  })
  xchatSync.resumeIncompleteJobs()
})
