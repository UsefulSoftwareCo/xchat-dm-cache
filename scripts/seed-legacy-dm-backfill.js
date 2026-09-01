import { DatabaseSync } from "node:sqlite"

const databasePath = process.argv[2]
if (!databasePath) throw new Error("Usage: node scripts/seed-legacy-dm-backfill.js <retired-birdclaw.sqlite>")

const publicBaseUrl = process.env.PUBLIC_BASE_URL
const apiKey = process.env.STATE_API_KEY
if (!publicBaseUrl || !apiKey) throw new Error("PUBLIC_BASE_URL and STATE_API_KEY are required")

const database = new DatabaseSync(databasePath, { readOnly: true })
const participantIds = database.prepare(`
  SELECT DISTINCT participant_profile_id AS id
  FROM dm_conversations
  WHERE participant_profile_id GLOB '[0-9]*'
    AND participant_profile_id != ''
  ORDER BY participant_profile_id
`).all().map((row) => row.id)
database.close()

if (participantIds.length === 0) throw new Error("No historical participant IDs were found")

const response = await fetch(new URL("/x/cache/legacy/backfill-jobs", publicBaseUrl), {
  method: "POST",
  headers: {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
  },
  body: JSON.stringify({
    participant_ids: participantIds,
    max_events: Math.max(1, Number(process.env.LEGACY_DM_BACKFILL_MAX_EVENTS) || 100_000),
    max_pages: Math.max(1, Number(process.env.LEGACY_DM_BACKFILL_MAX_PAGES) || 10_000),
  }),
})
if (!response.ok) throw new Error(`Backfill job creation failed with status ${response.status}`)
const job = await response.json()
console.log(JSON.stringify({ participant_count: participantIds.length, job_id: job.id, status: job.status }))
