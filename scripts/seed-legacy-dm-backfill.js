import { DatabaseSync } from "node:sqlite"

const databasePath = process.argv[2]
if (!databasePath) throw new Error("Usage: node scripts/seed-legacy-dm-backfill.js <retired-birdclaw.sqlite>")

const publicBaseUrl = process.env.PUBLIC_BASE_URL
const apiKey = process.env.STATE_API_KEY
if (!publicBaseUrl || !apiKey) throw new Error("PUBLIC_BASE_URL and STATE_API_KEY are required")

const database = new DatabaseSync(databasePath, { readOnly: true })
const profileIds = database.prepare(`
  SELECT DISTINCT participant_profile_id AS id
  FROM dm_conversations
  WHERE participant_profile_id != ''
  ORDER BY participant_profile_id
`).all().map((row) => String(row.id))
database.close()

const participantIds = profileIds
  .filter((value) => value.startsWith("profile_user_"))
  .map((value) => value.slice("profile_user_".length))
const conversationIds = profileIds
  .filter((value) => value.startsWith("profile_group_"))
  .map((value) => value.slice("profile_group_".length))
if (participantIds.length + conversationIds.length === 0) throw new Error("No historical DM targets were found")

const response = await fetch(new URL("/x/cache/legacy/backfill-jobs", publicBaseUrl), {
  method: "POST",
  headers: {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
  },
  body: JSON.stringify({
    participant_ids: participantIds,
    conversation_ids: conversationIds,
    max_events: Math.max(1, Number(process.env.LEGACY_DM_BACKFILL_MAX_EVENTS) || 100_000),
    max_pages: Math.max(1, Number(process.env.LEGACY_DM_BACKFILL_MAX_PAGES) || 10_000),
  }),
})
if (!response.ok) throw new Error(`Backfill job creation failed with status ${response.status}`)
const job = await response.json()
console.log(JSON.stringify({
  participant_count: participantIds.length,
  conversation_count: conversationIds.length,
  job_id: job.id,
  status: job.status,
}))
