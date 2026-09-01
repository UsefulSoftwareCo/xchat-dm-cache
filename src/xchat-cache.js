import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto"
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

function hash(value) {
  return createHash("sha256").update(value).digest("hex")
}

function encryptionKey(secret) {
  return Buffer.from(hkdfSync("sha256", secret, "executor-state-handler", "xchat-cache-v1", 32))
}

function seal(value, key) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, nonce)
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()])
  return [nonce, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64url")).join(".")
}

function open(sealed, key) {
  const [nonce, tag, encrypted] = sealed.split(".").map((part) => Buffer.from(part, "base64url"))
  const decipher = createDecipheriv("aes-256-gcm", key, nonce)
  decipher.setAuthTag(tag)
  return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"))
}

function normalizeSigningKey(value) {
  return {
    user_id: requiredString(value?.user_id, "signing_keys[].user_id"),
    public_key_version: requiredString(value?.public_key_version, "signing_keys[].public_key_version"),
    public_key: requiredString(value?.public_key, "signing_keys[].public_key"),
    signing_public_key: requiredString(value?.signing_public_key, "signing_keys[].signing_public_key"),
    identity_public_key_signature: requiredString(
      value?.identity_public_key_signature,
      "signing_keys[].identity_public_key_signature",
    ),
  }
}

function normalizeIdentity(value) {
  const juiceboxConfig = value?.juicebox_config
  if (!juiceboxConfig || typeof juiceboxConfig !== "object" || Array.isArray(juiceboxConfig)) {
    const error = new Error("identity.juicebox_config must be an object")
    error.status = 400
    throw error
  }
  return {
    user_id: requiredString(value?.user_id, "identity.user_id"),
    public_key_version: requiredString(value?.public_key_version, "identity.public_key_version"),
    juicebox_config: juiceboxConfig,
  }
}

function messageId(event, originalB64) {
  const signedId = event?.messageId ?? event?.message_id ?? event?.id
  return typeof signedId === "string" && signedId.length > 0
    ? signedId
    : hash(originalB64 ?? JSON.stringify(event))
}

export function webhookCrcResponse(crcToken, secret) {
  requiredString(crcToken, "crc_token")
  requiredString(secret, "X_WEBHOOK_CONSUMER_SECRET")
  const digest = createHmac("sha256", secret).update(crcToken).digest("base64")
  return `sha256=${digest}`
}

export function verifyWebhookSignature(rawBody, signature, secret) {
  if (!secret || typeof signature !== "string") return false
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("base64")}`)
  const supplied = Buffer.from(signature)
  return expected.length === supplied.length && timingSafeEqual(expected, supplied)
}

export class XChatCache {
  #db
  #decryptor
  #key
  #processing = null

  static async open({ filePath, decryptor, encryptionSecret }) {
    requiredString(filePath, "XCHAT_CACHE_FILE")
    requiredString(encryptionSecret, "STATE_API_KEY")
    await mkdir(dirname(filePath), { recursive: true })
    return new XChatCache({ database: new DatabaseSync(filePath), decryptor, encryptionSecret })
  }

  constructor({ database, decryptor, encryptionSecret }) {
    this.#db = database
    this.#decryptor = decryptor
    this.#key = encryptionKey(encryptionSecret)
    this.#migrate()
  }

  close() {
    this.#db.close()
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

  #migrate() {
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS xchat_cache_config (
        key TEXT PRIMARY KEY,
        value_encrypted TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS xchat_signing_keys (
        user_id TEXT NOT NULL,
        public_key_version TEXT NOT NULL,
        public_key TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        identity_public_key_signature TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (user_id, public_key_version)
      );
      CREATE TABLE IF NOT EXISTS xchat_conversations (
        id TEXT PRIMARY KEY,
        type TEXT,
        participant_ids_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS xchat_key_events (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        encoded_event TEXT NOT NULL,
        created_at TEXT NOT NULL,
        source TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS xchat_key_events_conversation
        ON xchat_key_events (conversation_id, created_at);
      CREATE TABLE IF NOT EXISTS xchat_events (
        event_uuid TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        sender_id TEXT,
        encoded_event TEXT NOT NULL,
        transport_id TEXT,
        created_at TEXT,
        source TEXT NOT NULL,
        received_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        processed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS xchat_events_pending ON xchat_events (status, received_at);
      CREATE INDEX IF NOT EXISTS xchat_events_conversation ON xchat_events (conversation_id, created_at);
      CREATE TABLE IF NOT EXISTS xchat_decrypted_events (
        event_id TEXT PRIMARY KEY,
        event_uuid TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        sender_id TEXT,
        created_at TEXT NOT NULL,
        sequence_id TEXT,
        event_type TEXT NOT NULL,
        event_encrypted TEXT NOT NULL,
        inserted_at TEXT NOT NULL,
        FOREIGN KEY (event_uuid) REFERENCES xchat_events(event_uuid)
      );
      CREATE INDEX IF NOT EXISTS xchat_decrypted_events_latest
        ON xchat_decrypted_events (created_at DESC);
      CREATE INDEX IF NOT EXISTS xchat_decrypted_events_conversation
        ON xchat_decrypted_events (conversation_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS xchat_webhook_deliveries (
        delivery_id TEXT PRIMARY KEY,
        received_at TEXT NOT NULL,
        body_encrypted TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        duplicate_event_count INTEGER NOT NULL
      );
    `)
  }

  configure({ identity, signing_keys: signingKeys = [], conversations = [] }) {
    const normalizedIdentity = normalizeIdentity(identity)
    if (!Array.isArray(signingKeys)) {
      const error = new Error("signing_keys must be an array")
      error.status = 400
      throw error
    }
    const normalizedKeys = signingKeys.map(normalizeSigningKey)
    const updatedAt = nowIso()
    this.#transaction(() => {
      this.#db.prepare(`
        INSERT INTO xchat_cache_config (key, value_encrypted, updated_at)
        VALUES ('identity', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_encrypted = excluded.value_encrypted, updated_at = excluded.updated_at
      `).run(seal(normalizedIdentity, this.#key), updatedAt)
      this.#upsertSigningKeys(normalizedKeys, updatedAt)
      for (const conversation of conversations) this.#upsertConversation(conversation, updatedAt)
      this.#retryFailedEvents()
    })
    return { configured: true, signing_key_count: normalizedKeys.length, conversation_count: conversations.length }
  }

  addSigningKeys(signingKeys) {
    if (!Array.isArray(signingKeys) || signingKeys.length === 0) {
      const error = new Error("signing_keys must contain at least one key")
      error.status = 400
      throw error
    }
    const normalized = signingKeys.map(normalizeSigningKey)
    this.#transaction(() => {
      this.#upsertSigningKeys(normalized, nowIso())
      this.#retryFailedEvents()
    })
    return { signing_key_count: normalized.length }
  }

  #upsertSigningKeys(signingKeys, updatedAt) {
    const statement = this.#db.prepare(`
      INSERT INTO xchat_signing_keys (
        user_id, public_key_version, public_key, signing_public_key,
        identity_public_key_signature, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, public_key_version) DO UPDATE SET
        public_key = excluded.public_key,
        signing_public_key = excluded.signing_public_key,
        identity_public_key_signature = excluded.identity_public_key_signature,
        updated_at = excluded.updated_at
    `)
    for (const key of signingKeys) {
      statement.run(
        key.user_id,
        key.public_key_version,
        key.public_key,
        key.signing_public_key,
        key.identity_public_key_signature,
        updatedAt,
      )
    }
  }

  #retryFailedEvents() {
    this.#db.exec(`
      UPDATE xchat_events
      SET status = 'pending', attempts = 0, last_error = NULL
      WHERE status = 'failed'
    `)
  }

  #upsertConversation(conversation, updatedAt = nowIso()) {
    const id = requiredString(conversation?.id, "conversation.id")
    const participantIds = Array.isArray(conversation?.participant_ids)
      ? conversation.participant_ids.filter((value) => typeof value === "string")
      : []
    this.#db.prepare(`
      INSERT INTO xchat_conversations (id, type, participant_ids_json, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        type = excluded.type,
        participant_ids_json = excluded.participant_ids_json,
        updated_at = excluded.updated_at
    `).run(id, typeof conversation?.type === "string" ? conversation.type : null, JSON.stringify(participantIds), updatedAt)
  }

  ingestBackfill({ conversation, identity, signing_keys: signingKeys = [], key_events: keyEvents = [], events = [] }) {
    if (!conversation || typeof conversation !== "object") {
      const error = new Error("conversation is required")
      error.status = 400
      throw error
    }
    if (!Array.isArray(events) || !Array.isArray(keyEvents)) {
      const error = new Error("events and key_events must be arrays")
      error.status = 400
      throw error
    }
    if (identity) this.configure({ identity, signing_keys: signingKeys, conversations: [conversation] })
    else {
      if (signingKeys.length > 0) this.addSigningKeys(signingKeys)
      this.#upsertConversation(conversation)
    }

    const conversationId = requiredString(conversation.id, "conversation.id")
    let inserted = 0
    let duplicates = 0
    this.#transaction(() => {
      for (const encodedEvent of keyEvents) {
        if (typeof encodedEvent !== "string" || encodedEvent.length === 0) continue
        this.#insertKeyEvent({ conversationId, encodedEvent, createdAt: nowIso(), source: "backfill" })
      }
      for (const value of events) {
        const encodedEvent = requiredString(value?.encoded_event, "events[].encoded_event")
        const eventUuid = String(value?.event_uuid ?? value?.id ?? hash(encodedEvent))
        const result = this.#insertEvent({
          eventUuid,
          eventType: value?.event_type ?? "chat.history",
          conversationId: value?.conversation_id ?? conversationId,
          senderId: value?.sender_id,
          encodedEvent,
          transportId: value?.id,
          createdAt: value?.created_at,
          source: "backfill",
        })
        if (result) inserted += 1
        else duplicates += 1
      }
    })
    return { inserted, duplicates, key_event_count: keyEvents.length }
  }

  acceptWebhook(body, rawBody = Buffer.from(JSON.stringify(body))) {
    const values = Array.isArray(body?.data) ? body.data : [body?.data]
    const events = values.filter((value) => value && typeof value === "object")
    const receivedAt = nowIso()
    const deliveryId = hash(rawBody)
    let inserted = 0
    let duplicates = 0

    this.#transaction(() => {
      for (const value of events) {
        if (!["chat.received", "chat.sent", "chat.conversation_join"].includes(value.event_type)) continue
        const payload = value.payload ?? {}
        const conversationId = requiredString(payload.conversation_id, "data.payload.conversation_id")
        this.#upsertConversation({ id: conversationId }, receivedAt)
        if (payload.conversation_key_change_event) {
          this.#insertKeyEvent({
            conversationId,
            encodedEvent: payload.conversation_key_change_event,
            createdAt: receivedAt,
            source: "webhook",
          })
        }
        if (!payload.encoded_event) continue
        const result = this.#insertEvent({
          eventUuid: value.event_uuid ?? hash(payload.encoded_event),
          eventType: value.event_type,
          conversationId,
          senderId: payload.sender_id,
          encodedEvent: payload.encoded_event,
          source: "webhook",
          receivedAt,
        })
        if (result) inserted += 1
        else duplicates += 1
      }
      this.#db.prepare(`
        INSERT OR IGNORE INTO xchat_webhook_deliveries
          (delivery_id, received_at, body_encrypted, event_count, duplicate_event_count)
        VALUES (?, ?, ?, ?, ?)
      `).run(deliveryId, receivedAt, seal(body, this.#key), inserted, duplicates)
    })
    return { accepted: true, inserted, duplicates }
  }

  #insertKeyEvent({ conversationId, encodedEvent, createdAt, source }) {
    this.#db.prepare(`
      INSERT OR IGNORE INTO xchat_key_events (id, conversation_id, encoded_event, created_at, source)
      VALUES (?, ?, ?, ?, ?)
    `).run(hash(encodedEvent), conversationId, encodedEvent, createdAt, source)
  }

  #insertEvent({ eventUuid, eventType, conversationId, senderId, encodedEvent, transportId, createdAt, source, receivedAt = nowIso() }) {
    const result = this.#db.prepare(`
      INSERT OR IGNORE INTO xchat_events (
        event_uuid, event_type, conversation_id, sender_id, encoded_event,
        transport_id, created_at, source, received_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      requiredString(String(eventUuid), "event_uuid"),
      requiredString(String(eventType), "event_type"),
      requiredString(String(conversationId), "conversation_id"),
      typeof senderId === "string" ? senderId : null,
      requiredString(encodedEvent, "encoded_event"),
      transportId == null ? null : String(transportId),
      typeof createdAt === "string" ? createdAt : null,
      source,
      receivedAt,
    )
    return result.changes > 0
  }

  processPending({ limit = 100 } = {}) {
    if (this.#processing) return this.#processing
    this.#processing = this.#processPending(limit).finally(() => {
      this.#processing = null
    })
    return this.#processing
  }

  async #processPending(limit) {
    const boundedLimit = Math.max(1, Math.min(Number(limit) || 100, 1000))
    const rows = this.#db.prepare(`
      SELECT * FROM xchat_events
      WHERE status IN ('pending', 'failed') AND attempts < 10
      ORDER BY received_at ASC
      LIMIT ?
    `).all(boundedLimit)
    let processed = 0
    let failed = 0
    for (const row of rows) {
      try {
        await this.#processEvent(row)
        processed += 1
      } catch (error) {
        failed += 1
        this.#db.prepare(`
          UPDATE xchat_events
          SET status = 'failed', attempts = attempts + 1, last_error = ?
          WHERE event_uuid = ?
        `).run(String(error?.message ?? error).slice(0, 500), row.event_uuid)
      }
    }
    return { selected: rows.length, processed, failed }
  }

  async #processEvent(row) {
    const config = this.#db.prepare("SELECT value_encrypted FROM xchat_cache_config WHERE key = 'identity'").get()
    if (!config) throw new Error("XChat cache identity is not configured")
    const identity = open(config.value_encrypted, this.#key)
    const signingKeys = this.#db.prepare(`
      SELECT user_id, public_key_version, public_key, signing_public_key, identity_public_key_signature
      FROM xchat_signing_keys
    `).all()
    if (signingKeys.length === 0) throw new Error("XChat signing keys are not configured")
    const keyEvents = this.#db.prepare(`
      SELECT encoded_event FROM xchat_key_events
      WHERE conversation_id = ?
      ORDER BY created_at ASC, id ASC
    `).all(row.conversation_id).map((value) => value.encoded_event)

    const result = await this.#decryptor.decrypt({
      identity,
      signing_keys: signingKeys,
      key_events: keyEvents,
      events: [row.encoded_event],
    })
    const errors = Array.isArray(result?.errors) ? result.errors : []
    if (errors.length > 0) throw new Error(`Chat XDK returned ${errors.length} decryption error(s)`)
    const messages = Array.isArray(result?.messages) ? result.messages : []
    const insertedAt = nowIso()
    this.#transaction(() => {
      for (const value of messages) {
        const event = value?.event
        if (!event || typeof event !== "object") continue
        const id = messageId(event, value.originalB64)
        const createdAt = Number.isFinite(event.createdAtMsec)
          ? new Date(event.createdAtMsec).toISOString()
          : row.created_at ?? row.received_at
        this.#db.prepare(`
          INSERT OR IGNORE INTO xchat_decrypted_events (
            event_id, event_uuid, conversation_id, sender_id, created_at,
            sequence_id, event_type, event_encrypted, inserted_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          id,
          row.event_uuid,
          row.conversation_id,
          event.senderId ?? row.sender_id,
          createdAt,
          event.sequenceId == null ? null : String(event.sequenceId),
          event.type,
          seal(event, this.#key),
          insertedAt,
        )
      }
      this.#db.prepare(`
        UPDATE xchat_events
        SET status = 'processed', attempts = attempts + 1, last_error = NULL, processed_at = ?
        WHERE event_uuid = ?
      `).run(insertedAt, row.event_uuid)
    })
  }

  listEvents({ limit = 50, before, after, conversation_id: conversationId, direction, event_type: eventType } = {}) {
    const boundedLimit = Math.max(1, Math.min(Number(limit) || 50, 100))
    const identity = this.#identityOrNull()
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
    if (direction === "sent" && identity) {
      clauses.push("sender_id = ?")
      parameters.push(identity.user_id)
    } else if (direction === "received" && identity) {
      clauses.push("sender_id != ?")
      parameters.push(identity.user_id)
    }
    if (eventType) {
      clauses.push("event_type = ?")
      parameters.push(eventType)
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""
    const rows = this.#db.prepare(`
      SELECT event_id, conversation_id, sender_id, created_at, sequence_id, event_type, event_encrypted
      FROM xchat_decrypted_events
      ${where}
      ORDER BY created_at DESC, event_id DESC
      LIMIT ?
    `).all(...parameters, boundedLimit)
    return {
      data: rows.map(({ event_encrypted: encrypted, ...row }) => ({
        ...row,
        direction: identity && row.sender_id === identity.user_id ? "sent" : "received",
        event: open(encrypted, this.#key),
      })),
      meta: {
        result_count: rows.length,
        next_before: rows.length === boundedLimit ? rows.at(-1).created_at : null,
      },
    }
  }

  listMessages(options = {}) {
    return this.listEvents({ ...options, event_type: "message" })
  }

  listConversations({ limit = 50 } = {}) {
    const boundedLimit = Math.max(1, Math.min(Number(limit) || 50, 100))
    const rows = this.#db.prepare(`
      SELECT
        c.id,
        c.type,
        c.participant_ids_json,
        COUNT(m.event_id) AS message_count,
        MAX(m.created_at) AS last_message_at
      FROM xchat_conversations c
      LEFT JOIN xchat_decrypted_events m ON m.conversation_id = c.id AND m.event_type = 'message'
      GROUP BY c.id
      ORDER BY last_message_at DESC, c.updated_at DESC
      LIMIT ?
    `).all(boundedLimit)
    return {
      data: rows.map(({ participant_ids_json: participantIds, ...row }) => ({
        ...row,
        participant_ids: JSON.parse(participantIds),
      })),
      meta: { result_count: rows.length },
    }
  }

  status() {
    const count = (table, where = "") => this.#db.prepare(`SELECT COUNT(*) AS count FROM ${table} ${where}`).get().count
    return {
      configured: Boolean(this.#identityOrNull()),
      signing_keys: count("xchat_signing_keys"),
      conversations: count("xchat_conversations"),
      events: count("xchat_events"),
      pending_events: count("xchat_events", "WHERE status IN ('pending', 'failed')"),
      decrypted_events: count("xchat_decrypted_events"),
      messages: count("xchat_decrypted_events", "WHERE event_type = 'message'"),
      webhook_deliveries: count("xchat_webhook_deliveries"),
    }
  }

  #identityOrNull() {
    const row = this.#db.prepare("SELECT value_encrypted FROM xchat_cache_config WHERE key = 'identity'").get()
    return row ? open(row.value_encrypted, this.#key) : null
  }
}
