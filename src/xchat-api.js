import { Client } from "@xdevplatform/xdk"

const publicKeyFields = [
  "public_key_version",
  "public_key",
  "signing_public_key",
  "identity_public_key_signature",
]
const identityFields = [...publicKeyFields, "juicebox_config"]

function mapSigningKey(userId, key) {
  return {
    user_id: userId,
    public_key_version: String(key.publicKeyVersion),
    public_key: key.publicKey,
    signing_public_key: key.signingPublicKey,
    identity_public_key_signature: key.identityPublicKeySignature,
  }
}

function apiError(response, operation) {
  const errors = Array.isArray(response?.errors) ? response.errors : []
  if (errors.length === 0) return
  const error = new Error(`${operation} failed: ${errors.map((value) => value.detail ?? value.title ?? "X API error").join("; ")}`)
  error.status = errors.find((value) => Number(value.status))?.status
  throw error
}

export class XChatApi {
  #client
  #clientFactory
  #accessToken
  #refreshToken
  #clientId
  #clientSecret
  #fetch
  #lastPublicKeyReadAt = null
  #now
  #publicKeyReadQueue = Promise.resolve()
  #publicKeyReadSpacingMs
  #sleep
  #tokenStore
  #loadedStoredToken = false

  constructor({
    accessToken,
    refreshToken,
    clientId,
    clientSecret,
    client,
    clientFactory = (token) => new Client({ accessToken: token }),
    fetchImpl = fetch,
    tokenStore,
    publicKeyReadSpacingMs = 900,
    now = Date.now,
    sleepImpl = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)),
  } = {}) {
    this.#accessToken = accessToken
    this.#refreshToken = refreshToken
    this.#clientId = clientId
    this.#clientSecret = clientSecret
    this.#fetch = fetchImpl
    this.#now = now
    this.#publicKeyReadSpacingMs = publicKeyReadSpacingMs
    this.#sleep = sleepImpl
    this.#tokenStore = tokenStore
    this.#clientFactory = clientFactory
    this.#client = client ?? (accessToken ? this.#clientFactory(accessToken) : null)
  }

  get configured() {
    return Boolean(this.#client || this.#accessToken || (this.#refreshToken && this.#clientId))
  }

  setTokenStore(tokenStore) {
    this.#tokenStore = tokenStore
    this.#loadedStoredToken = false
  }

  async #call(operation) {
    await this.#loadStoredToken()
    if (!this.#client) await this.#refreshAccessToken()
    try {
      return await operation(this.#client)
    } catch (error) {
      if (!this.#canRefresh() || !this.#isUnauthorized(error)) throw error
      await this.#refreshAccessToken()
      return operation(this.#client)
    }
  }

  #pacedPublicKeyRead(operation) {
    const run = this.#publicKeyReadQueue.then(async () => {
      if (this.#lastPublicKeyReadAt !== null) {
        const delayMs = Math.max(0, this.#lastPublicKeyReadAt + this.#publicKeyReadSpacingMs - this.#now())
        if (delayMs > 0) await this.#sleep(delayMs)
      }
      this.#lastPublicKeyReadAt = this.#now()
      return operation()
    })
    this.#publicKeyReadQueue = run.then(() => undefined, () => undefined)
    return run
  }

  async #loadStoredToken() {
    if (this.#loadedStoredToken) return
    this.#loadedStoredToken = true
    const stored = this.#tokenStore?.get?.()
    if (!stored || typeof stored !== "object") return
    if (typeof stored.access_token === "string") {
      this.#accessToken = stored.access_token
      this.#client = this.#clientFactory(this.#accessToken)
    }
    if (typeof stored.refresh_token === "string") this.#refreshToken = stored.refresh_token
  }

  #canRefresh() {
    return Boolean(this.#refreshToken && this.#clientId)
  }

  #isUnauthorized(error) {
    return Number(error?.status ?? error?.response?.status) === 401 || /\b401\b|unauthorized|expired token/i.test(String(error?.message ?? ""))
  }

  async #refreshAccessToken() {
    if (!this.#canRefresh()) throw new Error("X OAuth 2.0 user access token is not configured or cannot be refreshed")
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: this.#refreshToken,
      client_id: this.#clientId,
    })
    const headers = { "content-type": "application/x-www-form-urlencoded" }
    if (this.#clientSecret) {
      headers.authorization = `Basic ${Buffer.from(`${this.#clientId}:${this.#clientSecret}`).toString("base64")}`
    }
    const response = await this.#fetch("https://api.x.com/2/oauth2/token", { method: "POST", headers, body })
    if (!response.ok) throw new Error(`X OAuth token refresh failed with status ${response.status}`)
    const tokens = await response.json()
    if (typeof tokens?.access_token !== "string") throw new Error("X OAuth token refresh returned no access token")
    this.#accessToken = tokens.access_token
    if (typeof tokens.refresh_token === "string") this.#refreshToken = tokens.refresh_token
    this.#client = this.#clientFactory(this.#accessToken)
    this.#tokenStore?.set?.({
      access_token: this.#accessToken,
      refresh_token: this.#refreshToken,
      expires_at: Number.isFinite(tokens.expires_in) ? Date.now() + (tokens.expires_in * 1000) : null,
    })
  }

  async listConversations({ paginationToken, maxResults = 100 } = {}) {
    if (!this.configured) throw new Error("X OAuth 2.0 user access token is not configured")
    const response = await this.#call(async (client) => {
      const value = await client.chat.getConversations({
        maxResults,
        paginationToken,
        chatConversationFields: ["id", "type", "created_at", "updated_at"],
        expansions: ["participant_ids"],
      })
      apiError(value, "List XChat conversations")
      return value
    })
    return {
      data: (response.data ?? []).map((conversation) => ({
        id: conversation.id,
        type: conversation.type,
        participant_ids: conversation.participantIds ?? [],
      })),
      next_token: response.meta?.nextToken ?? null,
      has_more: response.meta?.hasMore ?? Boolean(response.meta?.nextToken),
    }
  }

  async listConversationEvents(conversationId, { paginationToken, maxResults = 100 } = {}) {
    if (!this.configured) throw new Error("X OAuth 2.0 user access token is not configured")
    const response = await this.#call(async (client) => {
      const value = await client.chat.getConversationEvents(conversationId, {
        maxResults,
        paginationToken,
        chatMessageEventFields: ["conversation_id", "created_at", "encoded_event", "id", "sender_id"],
      })
      apiError(value, `List XChat events for ${conversationId}`)
      return value
    })
    return {
      events: (response.data ?? []).map((event) => ({
        event_uuid: event.id,
        id: event.id,
        conversation_id: event.conversationId,
        sender_id: event.senderId,
        encoded_event: event.encodedEvent,
        created_at: event.createdAt,
      })),
      key_events: response.meta?.conversationKeyEvents ?? [],
      next_token: response.meta?.nextToken ?? null,
      has_more: response.meta?.hasMore ?? Boolean(response.meta?.nextToken),
    }
  }

  async getSigningKeys(userId) {
    if (!this.configured) throw new Error("X OAuth 2.0 user access token is not configured")
    const response = await this.#call(async (client) => {
      const value = await this.#pacedPublicKeyRead(
        () => client.users.getPublicKey(userId, { publicKeyFields }),
      )
      apiError(value, `Get XChat signing keys for ${userId}`)
      return value
    })
    return (response.data ?? []).map((key) => mapSigningKey(userId, key))
  }

  async getIdentity(userId, publicKeyVersion) {
    if (!this.configured) throw new Error("X OAuth 2.0 user access token is not configured")
    const response = await this.#call(async (client) => {
      const value = await this.#pacedPublicKeyRead(
        () => client.users.getPublicKey(userId, { publicKeyFields: identityFields }),
      )
      apiError(value, `Get XChat identity for ${userId}`)
      return value
    })
    const keys = response.data ?? []
    const key = keys.find((value) => String(value.publicKeyVersion) === String(publicKeyVersion))
    if (!key) throw new Error("The current XChat public key version was not returned by X")
    if (!key.juiceboxConfig || typeof key.juiceboxConfig !== "object") {
      throw new Error("The current XChat identity has no Juicebox configuration")
    }
    return {
      identity: {
        user_id: userId,
        public_key_version: String(key.publicKeyVersion),
        juicebox_config: key.juiceboxConfig,
      },
      signing_keys: keys.map((value) => mapSigningKey(userId, value)),
    }
  }
}
