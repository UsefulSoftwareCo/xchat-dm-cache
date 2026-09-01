import { createServer } from "node:http"
import { dirname, resolve } from "node:path"
import { createHandler } from "./app.js"
import { JsonStore } from "./store.js"
import { XChatDecryptor } from "./xchat.js"
import { XChatCache } from "./xchat-cache.js"
import { XChatApi } from "./xchat-api.js"
import { XChatSync } from "./xchat-sync.js"
import { XChatPendingProcessor } from "./xchat-pending.js"
import { startXChatWorkers, xchatStartupRetryDelay } from "./xchat-startup.js"
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
const xchatPending = new XChatPendingProcessor({ cache: xchatCache })
const xchatSync = new XChatSync({ api: xchatApi, cache: xchatCache, pendingProcessor: xchatPending })

const server = createServer(createHandler({
  store,
  apiKey: process.env.STATE_API_KEY,
  publicBaseUrl: process.env.PUBLIC_BASE_URL,
  xchat,
  xchatCache,
  xchatSync,
  xchatPending,
  webhookSecret: process.env.X_WEBHOOK_CONSUMER_SECRET,
}))

function startWorkers() {
  void startXChatWorkers({ cache: xchatCache, pending: xchatPending, sync: xchatSync }).catch((error) => {
    const retryDelayMs = xchatStartupRetryDelay(error)
    console.log(JSON.stringify({
      component: "xchat_startup",
      event: "worker_start_failed",
      status: Number(error?.status ?? error?.response?.status) || null,
      retry_at: new Date(Date.now() + retryDelayMs).toISOString(),
      error_name: typeof error?.name === "string" ? error.name : "Error",
      error_message: String(error?.message ?? error)
        .replace(/https?:\/\/\S+/gi, "[url]")
        .replace(/[A-Za-z0-9_=-]{32,}/g, "[redacted]")
        .slice(0, 300),
    }))
    const timer = setTimeout(startWorkers, retryDelayMs)
    timer.unref()
  })
}

server.listen(port, "0.0.0.0", () => {
  console.log(`Executor state handler listening on port ${port}`)
  startWorkers()
})
