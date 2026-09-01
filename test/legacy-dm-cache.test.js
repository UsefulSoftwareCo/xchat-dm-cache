import assert from "node:assert/strict"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { LegacyDmCache } from "../src/legacy-dm-cache.js"

async function createCache() {
  const directory = await mkdtemp(join(tmpdir(), "legacy-dm-cache-"))
  return LegacyDmCache.open({ filePath: join(directory, "cache.sqlite"), encryptionSecret: "test-secret" })
}

test("stores legacy DM bodies encrypted and returns normalized messages", async () => {
  const cache = await createCache()
  cache.configure({ self_id: "self" })
  const event = {
    id: "event-1",
    event_type: "MessageCreate",
    dm_conversation_id: "self-sender",
    sender_id: "sender",
    participant_ids: ["self", "sender"],
    created_at: "2026-05-09T00:03:49.000Z",
    text: "private legacy message",
  }
  assert.deepEqual(cache.ingest({ events: [event], users: [{ id: "sender", username: "sender" }] }), { inserted: 1, duplicates: 0 })
  assert.deepEqual(cache.ingest({ events: [event] }), { inserted: 0, duplicates: 1 })

  const messages = cache.listMessages({ participant_id: "sender" })
  assert.equal(messages.data.length, 1)
  assert.equal(messages.data[0].direction, "received")
  assert.equal(messages.data[0].source, "legacy_dm")
  assert.equal(messages.data[0].event.text, "private legacy message")
  assert.equal(cache.status().messages, 1)
  cache.close()
})

test("ingests signed account activity DM webhooks idempotently", async () => {
  const cache = await createCache()
  cache.configure({ self_id: "self" })
  const body = {
    direct_message_events: [{
      id: "1750000000000000000",
      type: "message_create",
      message_create: {
        sender_id: "sender",
        target: { recipient_id: "self" },
        message_data: { text: "webhook message" },
      },
    }],
  }
  assert.equal(cache.acceptWebhook(body).inserted, 1)
  assert.equal(cache.acceptWebhook(body).duplicates, 1)
  assert.equal(cache.listMessages().data[0].event.text, "webhook message")
  cache.close()
})

test("checkpoints participant backfill targets", async () => {
  const cache = await createCache()
  const job = cache.createBackfillJob({ participant_ids: ["one", "two", "one"], max_events: 100, max_pages: 10 })
  assert.equal(job.targets.total, 2)
  const target = cache.nextBackfillTarget(job.id)
  assert.equal(target.participant_id, "one")
  cache.updateBackfillTarget(job.id, "one", { status: "completed", pages_fetched: 1, events_seen: 2 })
  assert.equal(cache.nextBackfillTarget(job.id).participant_id, "two")
  cache.close()
})
