import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from "node:crypto"
import { mkdir } from "node:fs/promises"
import { dirname } from "node:path"
import { DatabaseSync } from "node:sqlite"

const nowIso = () => new Date().toISOString()

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    const error = new Error(`${name} is required`)
    error.status = 400
    throw error
  }
  return value
}

function encryptionKey(secret) {
  return Buffer.from(hkdfSync("sha256", secret, "executor-state-handler", "legacy-dm-cache-v1", 32))
}

function seal(value, key) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, nonce)
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()])
  return ["v1", nonce, cipher.getAuthTag(), encrypted]
    .map((part) => Buffer.isBuffer(part) ? part.toString("base64url") : part)
    .join(".")
}

function open(value, key) {
  const [version, nonceValue, tagValue, encryptedValue] = value.split(".")
  if (version !== "v1" || !encryptedValue) throw new Error("Unsupported legacy DM cache ciphertext version")
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(nonceValue, "base64url"))
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"))
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(encryptedValue, "base64url")),
    decipher.final(),
  ]).toString("utf8"))
}

function boundedInteger(value, fallback, maximum) {
  return Math.max(1, Math.min(Number(value) || fallback, maximum))
}

function snowflakeCreatedAt(value) {
  try {
    return new Date(Number((BigInt(value) >> 22n) + 1288834974657n)).toISOString()
  } catch {
    return nowIso()
  }
}

function normalizeEvent(value, source, selfId) {
  if (value?.message_create) {
    const senderId = requiredString(value.message_create.sender_id, "direct_message_events[].message_create.sender_id")
    const recipientId = requiredString(value.message_create.target?.recipient_id, "direct_message_events[].message_create.target.recipient_id")
    return {
      id: requiredString(String(value.id), "direct_message_events[].id"),
      event_type: "MessageCreate",
      conversation_id: [senderId, recipientId].sort().join("-"),
      sender_id: senderId,
      participant_ids: [senderId, recipientId],
      created_at: value.created_timestamp
        ? new Date(Number(value.created_timestamp)).toISOString()
        : snowflakeCreatedAt(value.id),
      text: value.message_create.message_data?.text ?? "",
      attachments: value.message_create.message_data?.attachment ? [value.message_create.message_data.attachment] : [],
      entities: value.message_create.message_data?.entities,
      source,
    }
  }

  const id = requiredString(String(value?.id ?? ""), "events[].id")
  const senderId = value?.sender_id ?? value?.senderId
  const participantIds = value?.participant_ids ?? value?.participantIds ?? []
  const normalizedParticipants = Array.isArray(participantIds)
    ? participantIds.map(String)
    : []
  const conversationId = value?.dm_conversation_id ?? value?.dmConversationId ?? (
    selfId && typeof senderId === "string" ? [selfId, senderId].sort().join("-") : null
  )
  return {
    id,
    event_type: requiredString(value?.event_type ?? value?.eventType, "events[].event_type"),
    conversation_id: requiredString(conversationId, "events[].dm_conversation_id"),
    sender_id: typeof senderId === "string" ? senderId : null,
    participant_ids: normalizedParticipants,
    created_at: requiredString(value?.created_at ?? value?.createdAt, "events[].created_at"),
    text: typeof value?.text === "string" ? value.text : "",
    attachments: value?.attachments ?? [],
    entities: value?.entities,
    source,
  }
}

export class LegacyDmCache {
  #db
  #key

  static async open({ filePath, encryptionSecret }) {
    requiredString(filePath, "LEGACY_DM_CACHE_FILE")
    requiredString(encryptionSecret, "XCHAT_CACHE_ENCRYPTION_KEY")
    await mkdir(dirname(filePath), { recursive: true })
    const database = new DatabaseSync(filePath)
    try {
      return new LegacyDmCache({ database, encryptionSecret })
    } catch (error) {
      database.close()
      throw error
    }
  }

  constructor({ database, encryptionSecret }) {
    this.#db = database
    this.#key = encryptionKey(encryptionSecret)
    this.#migrate()
    this.#ensureMarker()
  }

  close() {
    this.#db.close()
  }

  #migrate() {
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS legacy_dm_config (
        key TEXT PRIMARY KEY,
        value_encrypted TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS legacy_dm_users (
        user_id TEXT PRIMARY KEY,
        user_encrypted TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS legacy_dm_events (
        event_id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        sender_id TEXT,
        participant_ids_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event_encrypted TEXT NOT NULL,
        source TEXT NOT NULL,
        inserted_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS legacy_dm_events_latest
        ON legacy_dm_events (created_at DESC, event_id DESC);
      CREATE INDEX IF NOT EXISTS legacy_dm_events_conversation
        ON legacy_dm_events (conversation_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS legacy_dm_events_sender
        ON legacy_dm_events (sender_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS legacy_dm_backfill_jobs (
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
      CREATE TABLE IF NOT EXISTS legacy_dm_backfill_targets (
        job_id TEXT NOT NULL,
        participant_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        pagination_token TEXT,
        pages_fetched INTEGER NOT NULL DEFAULT 0,
        events_seen INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        PRIMARY KEY (job_id, participant_id),
        FOREIGN KEY (job_id) REFERENCES legacy_dm_backfill_jobs(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS legacy_dm_backfill_next
        ON legacy_dm_backfill_targets (job_id, status, position);
    `)
  }

  #ensureMarker() {
    const row = this.#db.prepare("SELECT value_encrypted FROM legacy_dm_config WHERE key = 'encryption_marker'").get()
    if (row) {
      if (open(row.value_encrypted, this.#key) !== "legacy-dm-cache-v1") {
        throw new Error("Invalid legacy DM cache encryption key")
      }
      return
    }
    this.#db.prepare("INSERT INTO legacy_dm_config (key, value_encrypted, updated_at) VALUES ('encryption_marker', ?, ?)")
      .run(seal("legacy-dm-cache-v1", this.#key), nowIso())
  }

  #transaction(action) {
    this.#db.exec("BEGIN IMMEDIATE")
    try {
      const result = action()
      this.#db.exec("COMMIT")
      return result
    } catch (error) {
      this.#db.exec("ROLLBACK")
      throw error
    }
  }

  setConfig(key, value) {
    this.#db.prepare(`
      INSERT INTO legacy_dm_config (key, value_encrypted, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value_encrypted = excluded.value_encrypted, updated_at = excluded.updated_at
    `).run(requiredString(key, "config key"), seal(value, this.#key), nowIso())
  }

  getConfig(key) {
    const row = this.#db.prepare("SELECT value_encrypted FROM legacy_dm_config WHERE key = ?").get(key)
    return row ? open(row.value_encrypted, this.#key) : null
  }

  configure({ self_id: selfId }) {
    this.setConfig("self_id", requiredString(selfId, "self_id"))
    return { configured: true }
  }

  ingest({ events = [], users = [], source = "api" }) {
    if (!Array.isArray(events) || !Array.isArray(users)) {
      const error = new Error("events and users must be arrays")
      error.status = 400
      throw error
    }
    const selfId = this.getConfig("self_id")
    const normalized = events.map((event) => normalizeEvent(event, source, selfId))
    const insertedAt = nowIso()
    let inserted = 0
    let duplicates = 0
    this.#transaction(() => {
      const userStatement = this.#db.prepare(`
        INSERT INTO legacy_dm_users (user_id, user_encrypted, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET user_encrypted = excluded.user_encrypted, updated_at = excluded.updated_at
      `)
      for (const user of users) {
        const userId = requiredString(String(user?.id ?? ""), "users[].id")
        userStatement.run(userId, seal(user, this.#key), insertedAt)
      }
      const eventStatement = this.#db.prepare(`
        INSERT OR IGNORE INTO legacy_dm_events (
          event_id, conversation_id, sender_id, participant_ids_json, created_at,
          event_type, event_encrypted, source, inserted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      for (const event of normalized) {
        const result = eventStatement.run(
          event.id,
          event.conversation_id,
          event.sender_id,
          JSON.stringify(event.participant_ids),
          event.created_at,
          event.event_type,
          seal(event, this.#key),
          source,
          insertedAt,
        )
        if (result.changes > 0) inserted += 1
        else duplicates += 1
      }
    })
    return { inserted, duplicates }
  }

  acceptWebhook(body) {
    const events = Array.isArray(body?.direct_message_events) ? body.direct_message_events : []
    const users = body?.users && typeof body.users === "object" ? Object.values(body.users) : []
    return { accepted: true, ...this.ingest({ events, users, source: "webhook" }) }
  }

  listEvents({ limit = 50, before, after, conversation_id: conversationId, participant_id: participantId, direction, event_type: eventType } = {}) {
    const boundedLimit = boundedInteger(limit, 50, 100)
    const selfId = this.getConfig("self_id")
    const clauses = []
    const parameters = []
    if (before) {
      clauses.push("created_at < ?")
      parameters.push(before)
    }
    if (after) {
      clauses.push("created_at > ?")
      parameters.push(after)
    }
    if (conversationId) {
      clauses.push("conversation_id = ?")
      parameters.push(conversationId)
    }
    if (participantId) {
      if (selfId) {
        clauses.push("(participant_ids_json LIKE ? OR conversation_id = ? OR conversation_id = ?)")
        parameters.push(`%\"${participantId}\"%`, `${selfId}-${participantId}`, `${participantId}-${selfId}`)
      } else {
        clauses.push("participant_ids_json LIKE ?")
        parameters.push(`%\"${participantId}\"%`)
      }
    }
    if (direction === "sent" && selfId) {
      clauses.push("sender_id = ?")
      parameters.push(selfId)
    } else if (direction === "received" && selfId) {
      clauses.push("sender_id != ?")
      parameters.push(selfId)
    }
    if (eventType) {
      clauses.push("event_type = ?")
      parameters.push(eventType)
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""
    const rows = this.#db.prepare(`
      SELECT event_id, conversation_id, sender_id, participant_ids_json, created_at,
        event_type, event_encrypted, source
      FROM legacy_dm_events
      ${where}
      ORDER BY created_at DESC, event_id DESC
      LIMIT ?
    `).all(...parameters, boundedLimit)
    return {
      data: rows.map(({ event_encrypted: encrypted, participant_ids_json: participants, ...row }) => ({
        ...row,
        source: "legacy_dm",
        transport_source: row.source,
        direction: selfId && row.sender_id === selfId ? "sent" : "received",
        participant_ids: JSON.parse(participants),
        event: open(encrypted, this.#key),
      })),
      meta: {
        result_count: rows.length,
        next_before: rows.length === boundedLimit ? rows.at(-1).created_at : null,
      },
    }
  }

  listMessages(options = {}) {
    return this.listEvents({ ...options, event_type: "MessageCreate" })
  }

  createBackfillJob({ participant_ids: participantIds, max_events: maxEvents, max_pages: maxPages }) {
    if (!Array.isArray(participantIds) || participantIds.length === 0) {
      const error = new Error("participant_ids must contain at least one user ID")
      error.status = 400
      throw error
    }
    const uniqueIds = [...new Set(participantIds.map((value) => requiredString(String(value), "participant_ids[]")))]
    const boundedEvents = Number(maxEvents)
    const boundedPages = Number(maxPages)
    if (!Number.isInteger(boundedEvents) || boundedEvents < 1 || !Number.isInteger(boundedPages) || boundedPages < 1) {
      const error = new Error("max_events and max_pages must be positive integers")
      error.status = 400
      throw error
    }
    const id = randomUUID()
    const timestamp = nowIso()
    this.#transaction(() => {
      this.#db.prepare(`
        INSERT INTO legacy_dm_backfill_jobs (id, status, max_events, max_pages, created_at, updated_at)
        VALUES (?, 'pending', ?, ?, ?, ?)
      `).run(id, boundedEvents, boundedPages, timestamp, timestamp)
      const insert = this.#db.prepare(`
        INSERT INTO legacy_dm_backfill_targets (job_id, participant_id, position)
        VALUES (?, ?, ?)
      `)
      uniqueIds.forEach((participantId, index) => insert.run(id, participantId, index + 1))
    })
    return this.getBackfillJob(id)
  }

  getBackfillJob(id) {
    const job = this.#db.prepare("SELECT * FROM legacy_dm_backfill_jobs WHERE id = ?").get(id)
    if (!job) return null
    const targets = this.#db.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
      FROM legacy_dm_backfill_targets WHERE job_id = ?
    `).get(id)
    return { ...job, targets }
  }

  listBackfillJobs({ limit = 20 } = {}) {
    return { data: this.#db.prepare("SELECT * FROM legacy_dm_backfill_jobs ORDER BY created_at DESC LIMIT ?")
      .all(boundedInteger(limit, 20, 100)) }
  }

  nextBackfillTarget(jobId) {
    return this.#db.prepare(`
      SELECT * FROM legacy_dm_backfill_targets
      WHERE job_id = ? AND status IN ('pending', 'running')
      ORDER BY position ASC LIMIT 1
    `).get(jobId)
  }

  updateBackfillJob(id, values) {
    const allowed = new Set(["status", "pages_fetched", "events_seen", "unique_events", "last_error"])
    const entries = Object.entries(values).filter(([key]) => allowed.has(key))
    if (entries.length === 0) return this.getBackfillJob(id)
    const assignments = entries.map(([key]) => `${key} = ?`).join(", ")
    this.#db.prepare(`UPDATE legacy_dm_backfill_jobs SET ${assignments}, updated_at = ? WHERE id = ?`)
      .run(...entries.map(([, value]) => value), nowIso(), id)
    return this.getBackfillJob(id)
  }

  updateBackfillTarget(jobId, participantId, values) {
    const allowed = new Set(["status", "pagination_token", "pages_fetched", "events_seen", "last_error"])
    const entries = Object.entries(values).filter(([key]) => allowed.has(key))
    if (entries.length === 0) return
    const assignments = entries.map(([key]) => `${key} = ?`).join(", ")
    this.#db.prepare(`UPDATE legacy_dm_backfill_targets SET ${assignments} WHERE job_id = ? AND participant_id = ?`)
      .run(...entries.map(([, value]) => value), jobId, participantId)
  }

  status() {
    const count = (table, where = "") => this.#db.prepare(`SELECT COUNT(*) AS count FROM ${table} ${where}`).get().count
    const range = this.#db.prepare("SELECT MIN(created_at) AS oldest, MAX(created_at) AS newest FROM legacy_dm_events").get()
    return {
      configured: Boolean(this.getConfig("self_id")),
      users: count("legacy_dm_users"),
      events: count("legacy_dm_events"),
      messages: count("legacy_dm_events", "WHERE event_type = 'MessageCreate'"),
      oldest_event_at: range.oldest,
      newest_event_at: range.newest,
      last_recent_sync_at: this.getConfig("last_recent_sync_at"),
      last_recent_sync_error: this.getConfig("last_recent_sync_error"),
    }
  }
}
