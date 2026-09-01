import { createHash } from "node:crypto"

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    const error = new Error(`${name} is required`)
    error.status = 400
    throw error
  }
  return value
}

function requiredStringArray(value, name) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    const error = new Error(`${name} must be an array of non-empty strings`)
    error.status = 400
    throw error
  }
  return value
}

function loadRealmTokens(juiceboxConfig) {
  const tokens = new Map()
  for (const entry of juiceboxConfig.token_map ?? juiceboxConfig.tokenMap ?? []) {
    const realm = String(entry?.key ?? "").toLowerCase()
    const token = entry?.value?.token
    if (realm && typeof token === "string") tokens.set(realm, token)
  }
  return tokens
}

function mapSigningKey(value) {
  return {
    userId: requiredString(value?.user_id, "signing_keys[].user_id"),
    publicKeyVersion: requiredString(value?.public_key_version, "signing_keys[].public_key_version"),
    publicKey: requiredString(value?.signing_public_key, "signing_keys[].signing_public_key"),
    identityPublicKey: requiredString(value?.public_key, "signing_keys[].public_key"),
    identityPublicKeySignature: requiredString(
      value?.identity_public_key_signature,
      "signing_keys[].identity_public_key_signature",
    ),
  }
}

function valueFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex")
}

function diagnosticError(error) {
  return {
    error_name: typeof error?.name === "string" ? error.name : "Error",
    error_message: String(error?.message ?? error)
      .replace(/https?:\/\/\S+/gi, "[url]")
      .replace(/[A-Za-z0-9_=-]{32,}/g, "[redacted]")
      .slice(0, 300),
  }
}

export class XChatDecryptor {
  #createChat
  #diagnostic
  #refreshIdentity
  #lastDiagnostic = null
  #pin
  #session
  #fingerprint
  #signingKeysFingerprint
  #hydratedKeySets = new Set()

  constructor({ createChat, pin, diagnostic = () => {}, refreshIdentity }) {
    this.#createChat = createChat
    this.#pin = pin
    this.#diagnostic = diagnostic
    this.#refreshIdentity = refreshIdentity
  }

  get configured() {
    return Boolean(this.#pin)
  }

  get diagnostics() {
    return this.#lastDiagnostic
  }

  #report(event, fields) {
    this.#lastDiagnostic = { event, ...fields, recorded_at: new Date().toISOString() }
    this.#diagnostic(event, fields)
  }

  async decrypt(body) {
    if (!this.#pin) {
      const error = new Error("XChat PIN is not configured")
      error.status = 503
      throw error
    }

    const identity = body?.identity
    const userId = requiredString(identity?.user_id, "identity.user_id")
    const publicKeyVersion = requiredString(
      identity?.public_key_version,
      "identity.public_key_version",
    )
    const juiceboxConfig = identity?.juicebox_config
    if (!juiceboxConfig || typeof juiceboxConfig !== "object" || Array.isArray(juiceboxConfig)) {
      const error = new Error("identity.juicebox_config must be an object")
      error.status = 400
      throw error
    }

    const events = requiredStringArray(body?.events, "events")
    const keyEvents = requiredStringArray(body?.key_events ?? [], "key_events")
    if (events.length + keyEvents.length === 0) {
      const error = new Error("at least one event or key event is required")
      error.status = 400
      throw error
    }

    if (!Array.isArray(body?.signing_keys) || body.signing_keys.length === 0) {
      const error = new Error("signing_keys must contain at least one public key")
      error.status = 400
      throw error
    }
    const signingKeys = body.signing_keys.map(mapSigningKey).sort((left, right) =>
      `${left.userId}\0${left.publicKeyVersion}`.localeCompare(`${right.userId}\0${right.publicKeyVersion}`),
    )

    let session
    try {
      session = await this.#getSession({ userId, publicKeyVersion, juiceboxConfig })
    } catch (error) {
      if (!this.#refreshIdentity || !/InvalidAuth/i.test(String(error?.message ?? error))) throw error
      this.#report("identity_refresh_started", {})
      let refreshedIdentity
      try {
        refreshedIdentity = await this.#refreshIdentity({ userId, publicKeyVersion })
      } catch (refreshError) {
        this.#report("identity_refresh_failed", diagnosticError(refreshError))
        throw refreshError
      }
      this.#report("identity_refresh_completed", {})
      session = await this.#getSession({
        userId: requiredString(refreshedIdentity?.user_id, "refreshed identity.user_id"),
        publicKeyVersion: requiredString(
          refreshedIdentity?.public_key_version,
          "refreshed identity.public_key_version",
        ),
        juiceboxConfig: refreshedIdentity?.juicebox_config,
      })
    }
    const signingKeysFingerprint = valueFingerprint(signingKeys)
    if (this.#signingKeysFingerprint !== signingKeysFingerprint) {
      session.setSigningKeys(signingKeys)
      this.#signingKeysFingerprint = signingKeysFingerprint
    }

    const keySetFingerprint = valueFingerprint(keyEvents)
    const hydrateKeys = keyEvents.length > 0 && !this.#hydratedKeySets.has(keySetFingerprint)
    const includedKeyEvents = hydrateKeys ? keyEvents : []
    const startedAt = Date.now()
    this.#report("decrypt_started", {
      key_event_count: includedKeyEvents.length,
      event_count: events.length,
    })
    let result
    try {
      result = session.decryptEvents([...includedKeyEvents, ...events])
    } catch (error) {
      this.#report("decrypt_failed", {
        key_event_count: includedKeyEvents.length,
        event_count: events.length,
        duration_ms: Date.now() - startedAt,
        ...diagnosticError(error),
      })
      throw error
    }
    this.#report("decrypt_completed", {
      key_event_count: includedKeyEvents.length,
      event_count: events.length,
      duration_ms: Date.now() - startedAt,
      error_count: Object.keys(result?.errors ?? {}).length,
      message_count: Array.isArray(result?.messages) ? result.messages.length : 0,
    })
    const errorIndexes = Object.keys(result?.errors ?? {}).map(Number).filter(Number.isFinite)
    if (hydrateKeys && errorIndexes.every((index) => index >= includedKeyEvents.length)) {
      this.#hydratedKeySets.add(keySetFingerprint)
    }
    return result
  }

  #getSession({ userId, publicKeyVersion, juiceboxConfig }) {
    const configJson = JSON.stringify(juiceboxConfig)
    const fingerprint = createHash("sha256")
      .update(userId)
      .update("\0")
      .update(publicKeyVersion)
      .update("\0")
      .update(configJson)
      .digest("hex")

    if (this.#session && this.#fingerprint === fingerprint) return this.#session

    const tokens = loadRealmTokens(juiceboxConfig)
    this.#fingerprint = fingerprint
    this.#signingKeysFingerprint = undefined
    this.#hydratedKeySets.clear()
    const unlockStartedAt = Date.now()
    this.#report("session_unlock_started", {})
    this.#session = Promise.resolve(
      this.#createChat({
        juiceboxConfig: configJson,
        getAuthToken: async (realmId) => tokens.get(String(realmId).toLowerCase()) ?? "",
      }),
    ).then(async (chat) => {
      await chat.unlock(this.#pin)
      chat.setIdentity(userId, publicKeyVersion)
      chat.setCacheKeys(true)
      this.#report("session_unlock_completed", { duration_ms: Date.now() - unlockStartedAt })
      return chat
    }).catch((error) => {
      this.#report("session_unlock_failed", {
        duration_ms: Date.now() - unlockStartedAt,
        ...diagnosticError(error),
      })
      this.#session = undefined
      this.#fingerprint = undefined
      this.#signingKeysFingerprint = undefined
      this.#hydratedKeySets.clear()
      throw error
    })
    return this.#session
  }
}
