import assert from "node:assert/strict"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { LegacyDmCache } from "../src/legacy-dm-cache.js"
import { LegacyDmSync } from "../src/legacy-dm-sync.js"

test("syncs recent events and completes a durable participant backfill", async () => {
  const directory = await mkdtemp(join(tmpdir(), "legacy-dm-sync-"))
  const cache = await LegacyDmCache.open({ filePath: join(directory, "cache.sqlite"), encryptionSecret: "test-secret" })
  let participantCalls = 0
  const api = {
    configured: true,
    getMe: async () => ({ id: "self" }),
    listLegacyDmEvents: async () => ({
      events: [{ id: "recent", event_type: "MessageCreate", dm_conversation_id: "self-a", sender_id: "a", participant_ids: ["self", "a"], created_at: "2026-09-01T00:00:00.000Z", text: "recent" }],
      users: [],
      next_token: null,
    }),
    listLegacyDmEventsByParticipant: async (participantId, { paginationToken }) => {
      participantCalls += 1
      return {
        events: [{ id: paginationToken ? "old-2" : "old-1", event_type: "MessageCreate", dm_conversation_id: `self-${participantId}`, sender_id: participantId, participant_ids: ["self", participantId], created_at: paginationToken ? "2025-01-01T00:00:00.000Z" : "2026-01-01T00:00:00.000Z", text: "old" }],
        users: [],
        next_token: paginationToken ? null : "next",
      }
    },
  }
  const sync = new LegacyDmSync({ api, cache })
  assert.deepEqual(await sync.syncRecent(), { pages: 1, seen: 1, inserted: 1, complete: true })
  const job = sync.createJob({ participant_ids: ["a"], max_events: 10, max_pages: 10 })
  const result = await sync.runJob(job.id)
  assert.equal(result.status, "completed")
  assert.equal(result.unique_events, 2)
  assert.equal(participantCalls, 2)
  assert.equal(cache.status().messages, 3)
  cache.close()
})

test("backfills group conversations and skips unavailable targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "legacy-dm-group-sync-"))
  const cache = await LegacyDmCache.open({ filePath: join(directory, "cache.sqlite"), encryptionSecret: "test-secret" })
  const calls = []
  const page = (id) => ({
    events: [{ id: `event-${id}`, event_type: "MessageCreate", dm_conversation_id: id, sender_id: "sender", participant_ids: ["self", "sender"], created_at: "2025-01-01T00:00:00.000Z", text: "old" }],
    users: [],
    next_token: null,
  })
  const api = {
    configured: true,
    getMe: async () => ({ id: "self" }),
    listLegacyDmEventsByParticipant: async (id) => {
      calls.push(["participant", id])
      if (id === "unavailable") throw Object.assign(new Error("HTTP 400: Bad Request"), { status: 400 })
      return page(id)
    },
    listLegacyDmEventsByConversation: async (id) => {
      calls.push(["conversation", id])
      return page(id)
    },
  }
  const sync = new LegacyDmSync({ api, cache })
  const job = sync.createJob({
    participant_ids: ["unavailable", "person"],
    conversation_ids: ["group"],
    max_events: 10,
    max_pages: 10,
  })
  const result = await sync.runJob(job.id)
  assert.equal(result.status, "completed")
  assert.equal(result.targets.completed, 2)
  assert.equal(result.targets.failed, 1)
  assert.deepEqual(calls, [
    ["participant", "unavailable"],
    ["participant", "person"],
    ["conversation", "group"],
  ])
  assert.equal(cache.status().messages, 2)
  cache.close()
})

test("leaves rate-limited backfills pending for a later retry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "legacy-dm-rate-limit-"))
  const cache = await LegacyDmCache.open({ filePath: join(directory, "cache.sqlite"), encryptionSecret: "test-secret" })
  let calls = 0
  const api = {
    configured: true,
    getMe: async () => ({ id: "self" }),
    listLegacyDmEventsByParticipant: async () => {
      calls += 1
      if (calls === 1) throw Object.assign(new Error("rate limited"), { status: 429, response: { headers: { "retry-after": "1" } } })
      return { events: [], users: [], next_token: null }
    },
  }
  const sync = new LegacyDmSync({ api, cache })
  const job = sync.createJob({ participant_ids: ["person"], max_events: 10, max_pages: 10 })
  assert.equal((await sync.runJob(job.id)).status, "pending")
  assert.equal((await sync.runJob(job.id)).status, "completed")
  cache.close()
})
