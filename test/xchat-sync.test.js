import assert from "node:assert/strict"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { XChatCache } from "../src/xchat-cache.js"
import { XChatSync } from "../src/xchat-sync.js"

const identity = { user_id: "self", public_key_version: "1", juicebox_config: {} }
const signingKey = (userId) => ({
  user_id: userId,
  public_key_version: "1",
  public_key: `identity-${userId}`,
  signing_public_key: `signing-${userId}`,
  identity_public_key_signature: `signature-${userId}`,
})

test("checkpoints and completes a bounded XChat archive backfill", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async ({ events }) => ({
        errors: [],
        messages: events.map((event) => ({
          originalB64: event,
          event: { id: `message-${event}`, type: "message", senderId: "sender", content: { text: event } },
        })),
      }),
    },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  const eventTokens = []
  const api = {
    configured: true,
    listConversations: async () => ({
      data: [{ id: "conversation-1", type: "direct", participant_ids: ["self", "sender"] }],
      next_token: null,
      has_more: false,
    }),
    getSigningKeys: async (userId) => [signingKey(userId)],
    listConversationEvents: async (_conversationId, { paginationToken }) => {
      eventTokens.push(paginationToken)
      return paginationToken
        ? { events: [{ event_uuid: "event-2", encoded_event: "ciphertext-2", sender_id: "sender" }], key_events: ["key-1", "key-2"], next_token: null, has_more: false }
        : { events: [{ event_uuid: "event-1", encoded_event: "ciphertext-1", sender_id: "sender" }], key_events: ["key-1", "key-2"], next_token: "next", has_more: true }
    },
  }
  const sync = new XChatSync({ api, cache })
  const created = sync.createJob({ max_events: 10, max_pages: 10 })
  const completed = await sync.runJob(created.id)

  assert.equal(completed.status, "completed")
  assert.equal(completed.events_seen, 2)
  assert.equal(completed.unique_events, 2)
  assert.deepEqual(eventTokens, [null, "next"])
  assert.equal(cache.status().messages, 2)
  assert.deepEqual(cache.listConversations().data[0].participant_ids, ["self", "sender"])
  cache.close()
})

test("pauses before reading beyond the configured event limit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-limit-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  const requestedSizes = []
  const api = {
    configured: true,
    listConversations: async () => ({ data: [{ id: "conversation-1", participant_ids: ["self"] }], next_token: null, has_more: false }),
    getSigningKeys: async (userId) => [signingKey(userId)],
    listConversationEvents: async (_id, { maxResults }) => {
      requestedSizes.push(maxResults)
      return { events: [{ event_uuid: "event-1", encoded_event: "ciphertext" }], key_events: [], next_token: "more", has_more: true }
    },
  }
  const sync = new XChatSync({ api, cache })
  const job = sync.createJob({ max_events: 1, max_pages: 10 })
  const result = await sync.runJob(job.id)

  assert.equal(result.status, "paused")
  assert.equal(result.events_seen, 1)
  assert.deepEqual(requestedSizes, [1])
  cache.close()
})

test("checkpoints rate limits and schedules a delayed retry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-rate-limit-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  let eventAttempts = 0
  const api = {
    configured: true,
    listConversations: async () => ({ data: [{ id: "conversation-1", participant_ids: ["self"] }], next_token: null, has_more: false }),
    getSigningKeys: async (userId) => [signingKey(userId)],
    listConversationEvents: async () => {
      eventAttempts += 1
      if (eventAttempts === 1) {
        const error = new Error("HTTP 429: Too Many Requests")
        error.status = 429
        throw error
      }
      return { events: [], key_events: [], next_token: null, has_more: false }
    },
  }
  const scheduled = []
  const sync = new XChatSync({
    api,
    cache,
    rateLimitDelayMs: 1234,
    scheduleTask: (callback, delayMs) => scheduled.push({ callback, delayMs }),
  })
  const job = sync.createJob({ max_events: 10, max_pages: 10 })

  sync.schedule(job.id)
  const initialRun = scheduled.shift()
  assert.equal(initialRun.delayMs, 0)
  await initialRun.callback()
  await new Promise(setImmediate)

  assert.equal(cache.getBackfillJob(job.id).status, "pending")
  assert.equal(cache.getBackfillJob(job.id).last_error, "X API rate limit reached; retry scheduled")
  assert.equal(scheduled[0].delayMs, 1234)

  await scheduled.shift().callback()
  await new Promise(setImmediate)

  assert.equal(cache.getBackfillJob(job.id).status, "completed")
  assert.equal(eventAttempts, 2)
  cache.close()
})

test("retries at the reset time reported by X", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-rate-reset-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  const api = {
    configured: true,
    listConversations: async () => ({ data: [{ id: "conversation-1", participant_ids: ["self"] }], next_token: null, has_more: false }),
    getSigningKeys: async () => [],
    listConversationEvents: async () => {
      const error = new Error("HTTP 429: Too Many Requests")
      error.status = 429
      error.headers = new Headers({ "x-rate-limit-reset": "1700000030" })
      throw error
    },
  }
  const scheduled = []
  const sync = new XChatSync({
    api,
    cache,
    now: () => 1700000000000,
    scheduleTask: (callback, delayMs) => scheduled.push({ callback, delayMs }),
  })
  const job = sync.createJob({ max_events: 10, max_pages: 10 })

  sync.schedule(job.id)
  await scheduled.shift().callback()
  await new Promise(setImmediate)

  assert.equal(scheduled[0].delayMs, 31000)
  cache.close()
})

test("reuses persisted signing keys across event pages", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-signing-keys-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  let signingKeyRequests = 0
  let eventPages = 0
  const api = {
    configured: true,
    listConversations: async () => ({ data: [{ id: "conversation-1", participant_ids: ["self", "sender"] }], next_token: null, has_more: false }),
    getSigningKeys: async (userId) => {
      signingKeyRequests += 1
      return [signingKey(userId)]
    },
    listConversationEvents: async () => {
      eventPages += 1
      return eventPages === 1
        ? { events: [], key_events: [], next_token: "next", has_more: true }
        : { events: [], key_events: [], next_token: null, has_more: false }
    },
  }
  const sync = new XChatSync({ api, cache })
  const job = sync.createJob({ max_events: 10, max_pages: 10 })

  const result = await sync.runJob(job.id)

  assert.equal(result.status, "completed")
  assert.equal(eventPages, 2)
  assert.equal(signingKeyRequests, 1)
  cache.close()
})

test("does not repeat an empty signing-key lookup on every event page", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-empty-signing-keys-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  let signingKeyRequests = 0
  let eventPages = 0
  const api = {
    configured: true,
    listConversations: async () => ({
      data: [{ id: "conversation-1", participant_ids: ["self", "no-key"] }],
      next_token: null,
      has_more: false,
    }),
    getSigningKeys: async () => {
      signingKeyRequests += 1
      return []
    },
    listConversationEvents: async () => {
      eventPages += 1
      return eventPages === 1
        ? { events: [], key_events: [], next_token: "next", has_more: true }
        : { events: [], key_events: [], next_token: null, has_more: false }
    },
  }
  const sync = new XChatSync({ api, cache })
  const job = sync.createJob({ max_events: 10, max_pages: 10 })

  const result = await sync.runJob(job.id)

  assert.equal(result.status, "completed")
  assert.equal(eventPages, 2)
  assert.equal(signingKeyRequests, 1)
  cache.close()
})

test("raises an existing backfill cap without losing its checkpoint", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-raise-limit-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  cache.configure({ identity, signing_keys: [signingKey("self")] })
  const job = cache.createBackfillJob({ max_events: 10, max_pages: 20 })
  cache.updateBackfillJob(job.id, {
    status: "paused",
    pages_fetched: 4,
    events_seen: 10,
    unique_events: 9,
    last_error: "Configured backfill limit reached",
  })

  const raised = cache.raiseBackfillJobLimits(job.id, { max_events: 50, max_pages: 100 })

  assert.equal(raised.status, "pending")
  assert.equal(raised.max_events, 50)
  assert.equal(raised.max_pages, 100)
  assert.equal(raised.pages_fetched, 4)
  assert.equal(raised.events_seen, 10)
  assert.equal(raised.unique_events, 9)
  assert.equal(raised.last_error, null)
  cache.close()
})

test("rejects an empty backfill limit update", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-sync-empty-limit-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: { decrypt: async () => ({ errors: [], messages: [] }) },
  })
  const job = cache.createBackfillJob({ max_events: 10, max_pages: 20 })

  assert.throws(() => cache.raiseBackfillJobLimits(job.id, {}), /max_events or max_pages is required/)
  cache.close()
})
