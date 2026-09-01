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

test("deduplicates backfill events and encrypts private values at rest", async () => {
  const { cache, calls, filePath } = await cacheFixture()
  const page = {
    conversation: { id: "conversation-1", type: "direct", participant_ids: ["self", "sender"] },
    key_events: ["conversation-key-event"],
    events: [{ event_uuid: "event-1", encoded_event: "ciphertext-1", sender_id: "sender" }],
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

test("retries failed events after signing keys are updated", async () => {
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
    events: [{ event_uuid: "retry-event", encoded_event: "retry-ciphertext" }],
  })
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 0, failed: 1 })
  shouldFail = false
  cache.addSigningKeys([{ ...signingKey, signing_public_key: "new-signing-public-key" }])
  assert.deepEqual(await cache.processPending(), { selected: 1, processed: 1, failed: 0 })
  cache.close()
})
