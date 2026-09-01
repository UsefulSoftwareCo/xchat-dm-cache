import assert from "node:assert/strict"
import { createHmac } from "node:crypto"
import { createServer } from "node:http"
import { after, before, test } from "node:test"
import { createHandler } from "../src/app.js"

const values = new Map()
const store = {
  get: (namespace, key) => values.get(`${namespace}/${key}`),
  list: (namespace) => [...values.keys()].filter((key) => key.startsWith(`${namespace}/`)).map((key) => key.slice(namespace.length + 1)),
  set: async (namespace, key, value) => values.set(`${namespace}/${key}`, value),
  delete: async (namespace, key) => values.delete(`${namespace}/${key}`),
}

let server
let baseUrl
const acceptedWebhooks = []
let processCount = 0

before(async () => {
  server = createServer(createHandler({
    store,
    apiKey: "test-secret",
    publicBaseUrl: "https://state.example.com",
    xchat: {
      configured: true,
      decrypt: async (body) => ({ messages: body.events.map((event) => ({ event })) }),
    },
    webhookSecret: "webhook-secret",
    xchatCache: {
      status: () => ({ messages: 0 }),
      acceptWebhook: (body, rawBody) => {
        acceptedWebhooks.push({ body, rawBody })
        return { accepted: true, inserted: 1, duplicates: 0 }
      },
      processPending: async () => { processCount += 1 },
    },
  }))
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  baseUrl = `http://127.0.0.1:${server.address().port}`
})

after(() => new Promise((resolve) => server.close(resolve)))

test("rejects unauthenticated state access", async () => {
  const response = await fetch(`${baseUrl}/state/test/key`)
  assert.equal(response.status, 401)
})

test("writes, reads, lists, and deletes JSON state", async () => {
  const headers = { authorization: "Bearer test-secret", "content-type": "application/json" }
  const put = await fetch(`${baseUrl}/state/test/key`, { method: "PUT", headers, body: JSON.stringify({ value: { enabled: true } }) })
  assert.equal(put.status, 200)

  const get = await fetch(`${baseUrl}/state/test/key`, { headers })
  assert.deepEqual(await get.json(), { namespace: "test", key: "key", value: { enabled: true } })

  const list = await fetch(`${baseUrl}/state/test`, { headers })
  assert.deepEqual(await list.json(), { keys: ["key"] })

  const deletion = await fetch(`${baseUrl}/state/test/key`, { method: "DELETE", headers })
  assert.deepEqual(await deletion.json(), { deleted: true })
})

test("publishes a valid OpenAPI document", async () => {
  const response = await fetch(`${baseUrl}/openapi.json`)
  const document = await response.json()
  assert.equal(document.openapi, "3.1.0")
  assert.equal(document.servers[0].url, "https://state.example.com")
  assert.equal(document.paths["/state/{namespace}/{key}"].put.operationId, "putStateValue")
  assert.equal(document.paths["/xchat/decrypt-events"].post.operationId, "decryptXChatEvents")
  assert.equal(document.paths["/xchat/cache/messages"].get.operationId, "listCachedXChatMessages")
  assert.equal(document.paths["/xchat/cache/events"].get.operationId, "listCachedXChatEvents")
})

test("answers X webhook CRC challenges", async () => {
  const response = await fetch(`${baseUrl}/xchat/webhook?crc_token=challenge`)
  assert.equal(response.status, 200)
  const expected = createHmac("sha256", "webhook-secret").update("challenge").digest("base64")
  assert.deepEqual(await response.json(), { response_token: `sha256=${expected}` })
})

test("rejects an invalid X webhook signature", async () => {
  const response = await fetch(`${baseUrl}/xchat/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-twitter-webhooks-signature": "sha256=invalid" },
    body: JSON.stringify({ data: {} }),
  })
  assert.equal(response.status, 401)
})

test("persists a signed X webhook before processing it", async () => {
  const body = JSON.stringify({ data: { event_type: "chat.received" } })
  const signature = `sha256=${createHmac("sha256", "webhook-secret").update(body).digest("base64")}`
  const response = await fetch(`${baseUrl}/xchat/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-twitter-webhooks-signature": signature },
    body,
  })
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { accepted: true, inserted: 1, duplicates: 0 })
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(acceptedWebhooks[0].body, JSON.parse(body))
  assert.deepEqual(acceptedWebhooks[0].rawBody, Buffer.from(body))
  assert.equal(processCount, 1)
})

test("passes authenticated XChat event batches to the decryptor", async () => {
  const response = await fetch(`${baseUrl}/xchat/decrypt-events`, {
    method: "POST",
    headers: { authorization: "Bearer test-secret", "content-type": "application/json" },
    body: JSON.stringify({ events: ["ciphertext"] }),
  })
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { messages: [{ event: "ciphertext" }] })
})
