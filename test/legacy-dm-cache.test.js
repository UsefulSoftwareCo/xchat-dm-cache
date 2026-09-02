import assert from "node:assert/strict"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { DatabaseSync } from "node:sqlite"
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
  assert.equal(cache.searchMessages({ query: "LEGACY private" }).data[0].event.text, "private legacy message")
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

test("checkpoints participant and conversation backfill targets", async () => {
  const cache = await createCache()
  const job = cache.createBackfillJob({
    participant_ids: ["one", "one"],
    conversation_ids: ["group-one"],
    max_events: 100,
    max_pages: 10,
  })
  assert.equal(job.targets.total, 2)
  const target = cache.nextBackfillTarget(job.id)
  assert.deepEqual([target.target_type, target.target_id], ["participant", "one"])
  cache.updateBackfillTarget(job.id, "participant", "one", { status: "completed", pages_fetched: 1, events_seen: 2 })
  assert.deepEqual(
    [cache.nextBackfillTarget(job.id).target_type, cache.nextBackfillTarget(job.id).target_id],
    ["conversation", "group-one"],
  )
  cache.close()
})

test("migrates existing participant checkpoints to typed targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "legacy-dm-cache-migration-"))
  const filePath = join(directory, "cache.sqlite")
  const database = new DatabaseSync(filePath)
  database.exec(`
    CREATE TABLE legacy_dm_backfill_jobs (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      max_events INTEGER NOT NULL,
      max_pages INTEGER NOT NULL,
      pages_fetched INTEGER NOT NULL DEFAULT 0,
      events_seen INTEGER NOT NULL DEFAULT 0,
      unique_events INTEGER NOT NULL DEFAULT 0,
      last_error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    INSERT INTO legacy_dm_backfill_jobs (id, status, max_events, max_pages, created_at, updated_at)
    VALUES ('old-job', 'pending', 10, 10, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z');
    CREATE TABLE legacy_dm_backfill_targets (
      job_id TEXT NOT NULL,
      participant_id TEXT NOT NULL,
      position INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      pagination_token TEXT,
      pages_fetched INTEGER NOT NULL DEFAULT 0,
      events_seen INTEGER NOT NULL DEFAULT 0,
      last_error TEXT,
      PRIMARY KEY (job_id, participant_id)
    );
    INSERT INTO legacy_dm_backfill_targets (job_id, participant_id, position)
    VALUES ('old-job', 'person', 1);
  `)
  database.close()

  const cache = await LegacyDmCache.open({ filePath, encryptionSecret: "test-secret" })
  assert.deepEqual(
    [cache.nextBackfillTarget("old-job").target_type, cache.nextBackfillTarget("old-job").target_id],
    ["participant", "person"],
  )
  cache.close()
})
