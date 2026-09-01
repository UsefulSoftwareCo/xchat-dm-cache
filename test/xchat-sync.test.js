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
