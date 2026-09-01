import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { mkdtemp } from "node:fs/promises"
import { test } from "node:test"
import { XChatCache } from "../src/xchat-cache.js"

const identity = {
  user_id: "self",
  public_key_version: "identity-v1",
  juicebox_config: { token_map: [{ key: "realm", value: { token: "private-token" } }] },
}

const signingKey = {
  user_id: "sender",
  public_key_version: "signing-v1",
  public_key: "identity-public-key",
  signing_public_key: "signing-public-key",
  identity_public_key_signature: "identity-signature",
}

function decryptor(calls) {
  return {
    decrypt: async (body) => {
      calls.push(body)
      return {
        messages: body.events.map((event) => ({
          originalB64: event,
          event: {
            type: "message",
            id: `message-${event}`,
            conversationId: "sdk:conversation-1",
            senderId: "sender",
            sequenceId: "7",
            content: { text: "private message body" },
          },
        })),
        errors: [],
      }
    },
  }
}

async function cacheFixture() {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-"))
  const filePath = join(directory, "cache.sqlite")
  const calls = []
  const cache = await XChatCache.open({
    filePath,
    decryptor: decryptor(calls),
    encryptionSecret: "test-state-api-key",
  })
  cache.configure({ identity, signing_keys: [signingKey], conversations: [{ id: "conversation-1" }] })
  return { cache, calls, filePath }
}

test("prepares decryption from the encrypted cached identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-prepare-"))
  const prepared = []
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    decryptor: {
      prepare: async (value) => prepared.push(value),
      decrypt: async () => ({ messages: [], errors: [] }),
    },
    encryptionSecret: "test-state-api-key",
  })
  assert.deepEqual(await cache.prepareDecryption(), { ready: false })
  cache.configure({ identity, signing_keys: [signingKey] })
  assert.deepEqual(await cache.prepareDecryption(), { ready: true })
  assert.deepEqual(prepared, [identity])
  cache.close()
})

test("deduplicates backfill events and encrypts private values at rest", async () => {
  const { cache, calls, filePath } = await cacheFixture()
  const page = {
    conversation: { id: "conversation-1", type: "direct", participant_ids: ["self", "sender"] },
    key_events: ["conversation-key-event"],
    events: [{
      event_uuid: "event-1",
      conversation_id: "sdk:conversation-1",
      encoded_event: "ciphertext-1",
      sender_id: "sender",
    }],
  }

  assert.deepEqual(cache.ingestBackfill(page), { inserted: 1, duplicates: 0, key_event_count: 1 })
  assert.deepEqual(cache.ingestBackfill(page), { inserted: 0, duplicates: 1, key_event_count: 1 })
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0].key_events, ["conversation-key-event"])
  assert.deepEqual(cache.status(), {
    configured: true,
    signing_keys: 1,
    conversations: 1,
    events: 1,
    pending_events: 0,
    retryable_events: 0,
    exhausted_events: 0,
    distinct_senders: 1,
    senders_without_keys: 0,
    missing_signing_key_user_ids: [],
    decrypted_events: 1,
    messages: 1,
    webhook_deliveries: 0,
  })
  const messages = cache.listMessages()
  assert.equal(messages.data[0].direction, "received")
  assert.equal(messages.data[0].conversation_id, "conversation-1")
  assert.equal(messages.data[0].event.conversationId, "sdk:conversation-1")
  assert.equal(messages.data[0].event.content.text, "private message body")
  cache.close()

  const bytes = await readFile(filePath)
  assert.equal(bytes.includes(Buffer.from("private message body")), false)
  assert.equal(bytes.includes(Buffer.from("private-token")), false)
})

test("decrypts pending events from one conversation in a batch", async () => {
  const { cache, calls } = await cacheFixture()
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [
      { event_uuid: "batch-1", encoded_event: "ciphertext-1" },
      { event_uuid: "batch-2", encoded_event: "ciphertext-2" },
    ],
  })

  assert.deepEqual(await cache.processPending(), { selected: 2, processed: 2, failed: 0 })
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0].events, ["ciphertext-1", "ciphertext-2"])
  assert.equal(cache.status().pending_events, 0)
  assert.equal(cache.status().messages, 2)
  cache.close()
})

test("falls back to isolated retries when a decryption batch has errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-batch-fallback-"))
  const calls = []
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        calls.push(body.events)
        if (body.events.length > 1) return { messages: [], errors: { "0": "bad event" } }
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: [
      { event_type: "chat.received", event_uuid: "fallback-1", payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "fallback-ciphertext-1" } },
      { event_type: "chat.received", event_uuid: "fallback-2", payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "fallback-ciphertext-2" } },
    ],
  })

  assert.deepEqual(await cache.processPending(), { selected: 2, processed: 2, failed: 0 })
  assert.deepEqual(calls, [
    ["fallback-ciphertext-1", "fallback-ciphertext-2"],
    ["fallback-ciphertext-1"],
    ["fallback-ciphertext-2"],
  ])
  cache.close()
})

test("commits successful historical events without isolated replay", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-history-partial-"))
  let calls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        calls += 1
        return {
          errors: { "0": "bad event" },
          messages: [{
            originalB64: body.events[1],
            event: { type: "message", id: "good-message", senderId: "sender", content: { text: "good" } },
          }],
        }
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [
      { event_uuid: "bad-history", encoded_event: "bad" },
      { event_uuid: "good-history", encoded_event: "good" },
    ],
  })

  assert.deepEqual(await cache.processPending(), { selected: 2, processed: 1, failed: 1 })
  assert.equal(calls, 1)
  assert.equal(cache.status().pending_events, 1)
  assert.equal(cache.status().messages, 1)
  cache.close()
})

test("does not fan out a batch infrastructure failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-batch-infrastructure-"))
  let calls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async () => {
        calls += 1
        const error = new Error("HTTP 429: Too Many Requests")
        error.status = 429
        throw error
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [
      { event_uuid: "infra-1", encoded_event: "infra-ciphertext-1" },
      { event_uuid: "infra-2", encoded_event: "infra-ciphertext-2" },
    ],
  })

  await assert.rejects(() => cache.processPending(), /429/)
  assert.equal(calls, 1)
  assert.equal(cache.status().pending_events, 2)
  cache.close()
})

test("stops isolated retries when a signing-key refresh is throttled", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-key-throttle-"))
  let decryptCalls = 0
  let keyCalls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async () => {
        decryptCalls += 1
        return { messages: [], errors: { "0": "missing signing key" } }
      },
    },
    signingKeyProvider: async () => {
      keyCalls += 1
      const error = new Error("HTTP 429: Too Many Requests")
      error.status = 429
      throw error
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: [
      { event_type: "chat.received", event_uuid: "throttled-1", payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "ciphertext-1" } },
      { event_type: "chat.received", event_uuid: "throttled-2", payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "ciphertext-2" } },
    ],
  })

  await assert.rejects(() => cache.processPending(), /429/)
  assert.equal(decryptCalls, 2)
  assert.equal(keyCalls, 1)
  assert.equal(cache.status().pending_events, 2)
  cache.close()
})

test("persists key events and pending ciphertext across a restart", async () => {
  const { cache, filePath } = await cacheFixture()
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    key_events: ["persisted-key-event"],
    events: [{ event_uuid: "event-restart", encoded_event: "ciphertext-restart" }],
  })
  cache.close()

  const calls = []
  const reopened = await XChatCache.open({
    filePath,
    decryptor: decryptor(calls),
    encryptionSecret: "test-state-api-key",
  })
  assert.deepEqual(await reopened.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.deepEqual(calls[0].key_events, ["persisted-key-event"])
  assert.equal(reopened.listMessages().data[0].event.content.text, "private message body")
  reopened.close()
})

test("rekeys every encrypted cache row atomically", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-rekey-"))
  const filePath = join(directory, "cache.sqlite")
  const original = await XChatCache.open({
    filePath,
    decryptor: decryptor([]),
    encryptionSecret: "old-cache-key",
  })
  original.configure({ identity, signing_keys: [signingKey] })
  original.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [{ event_uuid: "rekey-event", encoded_event: "rekey-ciphertext" }],
  })
  await original.processPending()
  original.close()

  const migrated = await XChatCache.open({
    filePath,
    decryptor: decryptor([]),
    encryptionSecret: "new-cache-key",
    previousEncryptionSecret: "old-cache-key",
  })
  assert.equal(migrated.listMessages().data[0].event.content.text, "private message body")
  migrated.close()

  await assert.rejects(
    XChatCache.open({ filePath, decryptor: decryptor([]), encryptionSecret: "old-cache-key" }),
    /cannot decrypt the existing cache/,
  )
  const reopened = await XChatCache.open({
    filePath,
    decryptor: decryptor([]),
    encryptionSecret: "new-cache-key",
  })
  assert.equal(reopened.status().messages, 1)
  reopened.close()
})

test("deduplicates live webhook deliveries and message events", async () => {
  const { cache } = await cacheFixture()
  const body = {
    data: {
      event_type: "chat.received",
      event_uuid: "webhook-event-1",
      payload: {
        conversation_id: "conversation-1",
        sender_id: "sender",
        encoded_event: "webhook-ciphertext",
        conversation_key_change_event: "webhook-key-event",
      },
    },
  }
  const rawBody = Buffer.from(JSON.stringify(body))
  assert.deepEqual(cache.acceptWebhook(body, rawBody), { accepted: true, inserted: 1, duplicates: 0 })
  assert.deepEqual(cache.acceptWebhook(body, rawBody), { accepted: true, inserted: 0, duplicates: 1 })
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.equal(cache.status().webhook_deliveries, 1)
  assert.equal(cache.status().messages, 1)
  cache.close()
})

test("retries webhook events after a decryption failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-retry-"))
  let attempts = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        attempts += 1
        if (attempts === 1) throw new Error("temporary decryptor failure")
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "webhook-retry-1",
      payload: {
        conversation_id: "conversation-1",
        sender_id: "sender",
        encoded_event: "retry-ciphertext",
      },
    },
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 0, failed: 1 })
  assert.equal(cache.status().pending_events, 1)
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.equal(cache.status().pending_events, 0)
  assert.equal(cache.status().messages, 1)
  cache.close()
})

test("accepts the conversation join event spelling emitted by X", async () => {
  const { cache } = await cacheFixture()
  const body = {
    data: {
      event_type: "chat.conversation.join",
      event_uuid: "webhook-join-1",
      payload: { conversation_id: "conversation-joined" },
    },
  }

  assert.deepEqual(cache.acceptWebhook(body), { accepted: true, inserted: 0, duplicates: 0 })
  assert.equal(cache.status().webhook_deliveries, 1)
  assert.equal(cache.status().conversations, 2)
  assert.equal(
    cache.listConversations().data.some((conversation) => conversation.id === "conversation-joined"),
    true,
  )
  cache.close()
})

test("preserves conversation metadata when a webhook only supplies an id", async () => {
  const { cache } = await cacheFixture()
  cache.ingestBackfill({
    conversation: { id: "conversation-1", type: "direct", participant_ids: ["self", "sender"] },
    events: [],
  })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "metadata-event",
      payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "ciphertext" },
    },
  })

  const [conversation] = cache.listConversations().data
  assert.equal(conversation.type, "direct")
  assert.deepEqual(conversation.participant_ids, ["self", "sender"])
  cache.close()
})

test("uses a stable tuple cursor when events have the same timestamp", async () => {
  const { cache } = await cacheFixture()
  const createdAt = "2024-01-01T00:00:00.000Z"
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: ["a", "b", "c"].map((id) => ({ event_uuid: id, encoded_event: id, created_at: createdAt })),
  })
  await cache.processPending()

  const first = cache.listMessages({ limit: 2 })
  const second = cache.listMessages({ limit: 2, before: first.meta.next_before })
  assert.equal(first.data.length, 2)
  assert.equal(second.data.length, 1)
  assert.notEqual(first.meta.next_before, createdAt)
  cache.close()
})

test("drains events inserted while processing is active", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-drain-"))
  let releaseFirst
  let firstStarted
  const gate = new Promise((resolve) => { releaseFirst = resolve })
  const started = new Promise((resolve) => { firstStarted = resolve })
  let calls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        calls += 1
        if (calls === 1) {
          firstStarted()
          await gate
        }
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({ conversation: { id: "conversation-1" }, events: [{ event_uuid: "first", encoded_event: "first" }] })
  const firstDrain = cache.processPending()
  await started
  cache.ingestBackfill({ conversation: { id: "conversation-1" }, events: [{ event_uuid: "second", encoded_event: "second" }] })
  const secondDrain = cache.processPending()
  releaseFirst()
  await Promise.all([firstDrain, secondDrain])

  assert.equal(calls, 2)
  assert.equal(cache.status().pending_events, 0)
  assert.equal(cache.status().messages, 2)
  cache.close()
})

test("returns after the requested pending-event limit", async () => {
  const { cache } = await cacheFixture()
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: ["one", "two", "three"].map((id) => ({ event_uuid: id, encoded_event: id })),
  })

  assert.deepEqual(await cache.processPending({ limit: 2 }), { selected: 2, processed: 2, failed: 0 })
  assert.equal(cache.status().pending_events, 1)
  assert.deepEqual(await cache.processPending({ limit: 2 }), { selected: 1, processed: 1, failed: 0 })
  cache.close()
})

test("replays conversation key events in ingestion order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-order-"))
  let observedKeyEvents
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        observedKeyEvents = body.key_events
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    key_events: ["first", "second"],
    events: [{ event_uuid: "ordered", encoded_event: "ordered" }],
  })
  await cache.processPending()

  assert.deepEqual(observedKeyEvents, ["first", "second"])
  cache.close()
})

test("retains non-message XChat events", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-events-"))
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async () => ({
        messages: [{ event: {
          type: "messageDeleted",
          id: "delete-event",
          conversationId: "conversation-1",
          senderId: "self",
          createdAtMsec: 1_700_000_000_000,
          sequenceIds: ["7"],
        } }],
        errors: [],
      }),
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [{ event_uuid: "delete-envelope", encoded_event: "delete-ciphertext" }],
  })
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.equal(cache.listMessages().data.length, 0)
  assert.equal(cache.listEvents({ event_type: "messageDeleted" }).data[0].event.sequenceIds[0], "7")
  assert.equal(cache.status().decrypted_events, 1)
  cache.close()
})

test("retries only failed events from senders whose signing keys changed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-retry-"))
  let shouldFail = true
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    decryptor: {
      decrypt: async (body) => {
        if (shouldFail) throw new Error("missing sender key")
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [{ event_uuid: "retry-event", sender_id: signingKey.user_id, encoded_event: "retry-ciphertext" }],
  })
  cache.ingestBackfill({
    conversation: { id: "conversation-2" },
    events: [{ event_uuid: "unrelated-event", sender_id: "unrelated-user", encoded_event: "unrelated-ciphertext" }],
  })
  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.deepEqual(await cache.processPending(), { selected: 2, processed: 0, failed: 2 })
  }
  assert.equal(cache.status().exhausted_events, 2)
  shouldFail = false
  cache.addSigningKeys([{ ...signingKey, signing_public_key: "new-signing-public-key" }])
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.equal(cache.status().exhausted_events, 1)
  cache.close()
})

test("refreshes a sender signing key once before failing decryption", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-refresh-"))
  const refreshedUsers = []
  let attempts = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    signingKeyProvider: async (userId) => {
      refreshedUsers.push(userId)
      return [{ ...signingKey, signing_public_key: "refreshed-signing-key" }]
    },
    decryptor: {
      decrypt: async (body) => {
        attempts += 1
        if (attempts === 1) return { messages: [], errors: [{ detail: "unknown signing key" }] }
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "refresh-event",
      payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "refresh-ciphertext" },
    },
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.deepEqual(refreshedUsers, ["sender"])
  assert.equal(attempts, 2)
  cache.close()
})

test("does not reset failed events for an unchanged signing key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-unchanged-key-"))
  let keyCalls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    signingKeyProvider: async () => {
      keyCalls += 1
      return [signingKey]
    },
    decryptor: {
      decrypt: async () => ({ messages: [], errors: { "0": "bad event" } }),
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "unchanged-key",
      payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "ciphertext" },
    },
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 0, failed: 1 })
  assert.equal(keyCalls, 1)
  assert.equal(cache.status().pending_events, 1)
  cache.close()
})

test("does not fetch signing keys while retrying historical events", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-history-key-"))
  let keyCalls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    signingKeyProvider: async () => {
      keyCalls += 1
      return [signingKey]
    },
    decryptor: { decrypt: async () => ({ messages: [], errors: { "0": "bad history" } }) },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [{ event_uuid: "history-key", sender_id: "sender", encoded_event: "ciphertext" }],
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 0, failed: 1 })
  assert.equal(keyCalls, 0)
  cache.close()
})

test("does not fetch a missing live sender key from the history credential", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-live-missing-key-"))
  let keyCalls = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    signingKeyProvider: async () => {
      keyCalls += 1
      return []
    },
    decryptor: { decrypt: async () => ({ messages: [], errors: { "0": "missing sender key" } }) },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "live-missing-key",
      payload: { conversation_id: "conversation-1", sender_id: "missing", encoded_event: "ciphertext" },
    },
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 0, failed: 1 })
  assert.equal(keyCalls, 0)
  cache.close()
})

test("lists missing signing-key users with a stable private cursor", async () => {
  const { cache } = await cacheFixture()
  cache.ingestBackfill({
    conversation: { id: "conversation-1" },
    events: [
      { event_uuid: "known", sender_id: "sender", encoded_event: "known" },
      { event_uuid: "missing-a", sender_id: "missing-a", encoded_event: "missing-a" },
      { event_uuid: "missing-b", sender_id: "missing-b", encoded_event: "missing-b" },
    ],
  })

  const first = cache.listMissingSigningKeyUsers({ limit: 1 })
  const second = cache.listMissingSigningKeyUsers({ limit: 1, after: first.meta.next_after })
  assert.deepEqual(first.data, [{ user_id: "missing-a" }])
  assert.deepEqual(second.data, [{ user_id: "missing-b" }])
  cache.close()
})

test("recognizes the object-shaped error map returned by the Chat XDK", async () => {
  const directory = await mkdtemp(join(tmpdir(), "xchat-cache-error-map-"))
  const refreshedUsers = []
  let attempts = 0
  const cache = await XChatCache.open({
    filePath: join(directory, "cache.sqlite"),
    encryptionSecret: "test-state-api-key",
    signingKeyProvider: async (userId) => {
      refreshedUsers.push(userId)
      return [{ ...signingKey, signing_public_key: "refreshed-signing-key" }]
    },
    decryptor: {
      decrypt: async (body) => {
        attempts += 1
        if (attempts === 1) return { messages: [], errors: { "0": "unknown signing key" } }
        return decryptor([]).decrypt(body)
      },
    },
  })
  cache.configure({ identity, signing_keys: [signingKey] })
  cache.acceptWebhook({
    data: {
      event_type: "chat.received",
      event_uuid: "error-map-event",
      payload: { conversation_id: "conversation-1", sender_id: "sender", encoded_event: "error-map-ciphertext" },
    },
  })

  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  assert.deepEqual(refreshedUsers, ["sender"])
  assert.equal(attempts, 2)
  cache.close()
})
