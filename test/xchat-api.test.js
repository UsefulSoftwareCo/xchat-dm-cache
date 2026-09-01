import assert from "node:assert/strict"
import { test } from "node:test"
import { XChatApi } from "../src/xchat-api.js"

test("maps official XDK chat responses into cache input", async () => {
  const client = {
    chat: {
      getConversations: async () => ({
        data: [{ id: "conversation-1", type: "direct", participantIds: ["self", "sender"] }],
        meta: { hasMore: false },
      }),
      getConversationEvents: async () => ({
        data: [{ id: "event-1", conversationId: "conversation-1", senderId: "sender", encodedEvent: "ciphertext", createdAt: "2024-01-01T00:00:00.000Z" }],
        meta: { conversationKeyEvents: ["key-event"], nextToken: "next", hasMore: true },
      }),
    },
    users: {
      getPublicKey: async () => ({ data: [{ publicKeyVersion: "1", publicKey: "identity", signingPublicKey: "signing", identityPublicKeySignature: "signature" }] }),
      getMe: async () => ({ data: { id: "self", name: "Rhys", username: "RhysSullivan" } }),
    },
    directMessages: {
      getEvents: async () => ({
        data: [{ id: "dm-1", eventType: "MessageCreate", dmConversationId: "self-sender", senderId: "sender", participantIds: ["self", "sender"], createdAt: "2024-02-01T00:00:00.000Z", text: "hello" }],
        includes: { users: [{ id: "sender", name: "Sender", username: "sender" }] },
        meta: { nextToken: "legacy-next" },
      }),
      getEventsByParticipantId: async (participantId) => ({
        data: [{ id: "dm-2", eventType: "MessageCreate", dmConversationId: `self-${participantId}`, senderId: participantId, participantIds: ["self", participantId], createdAt: "2023-02-01T00:00:00.000Z", text: "older" }],
        meta: {},
      }),
      getEventsByConversationId: async (conversationId) => ({
        data: [{ id: "dm-3", eventType: "MessageCreate", dmConversationId: conversationId, senderId: "sender", participantIds: ["self", "sender"], createdAt: "2022-02-01T00:00:00.000Z", text: "group" }],
        meta: {},
      }),
    },
  }
  const api = new XChatApi({ client })

  assert.deepEqual(await api.listConversations(), {
    data: [{ id: "conversation-1", type: "direct", participant_ids: ["self", "sender"] }],
    next_token: null,
    has_more: false,
  })
  assert.deepEqual(await api.listConversationEvents("conversation-1"), {
    events: [{
      event_uuid: "event-1",
      id: "event-1",
      conversation_id: "conversation-1",
      sender_id: "sender",
      encoded_event: "ciphertext",
      created_at: "2024-01-01T00:00:00.000Z",
    }],
    key_events: ["key-event"],
    next_token: "next",
    has_more: true,
  })
  assert.deepEqual(await api.getSigningKeys("sender"), [{
    user_id: "sender",
    public_key_version: "1",
    public_key: "identity",
    signing_public_key: "signing",
    identity_public_key_signature: "signature",
  }])
  assert.deepEqual(await api.getMe(), { id: "self", name: "Rhys", username: "RhysSullivan" })
  assert.deepEqual(await api.listLegacyDmEvents(), {
    events: [{
      id: "dm-1",
      event_type: "MessageCreate",
      dm_conversation_id: "self-sender",
      sender_id: "sender",
      participant_ids: ["self", "sender"],
      created_at: "2024-02-01T00:00:00.000Z",
      text: "hello",
      attachments: undefined,
      entities: undefined,
    }],
    users: [{ id: "sender", name: "Sender", username: "sender" }],
    next_token: "legacy-next",
  })
  assert.equal((await api.listLegacyDmEventsByParticipant("sender")).events[0].id, "dm-2")
  assert.equal((await api.listLegacyDmEventsByConversation("group")).events[0].id, "dm-3")
})

test("refreshes an expired OAuth token and persists the rotated token", async () => {
  const createdTokens = []
  const stored = []
  const clientFactory = (token) => {
    createdTokens.push(token)
    return {
      chat: {
        getConversations: async () => {
          if (token === "expired") {
            const error = new Error("Unauthorized")
            error.status = 401
            throw error
          }
          return { data: [], meta: { hasMore: false } }
        },
      },
    }
  }
  const api = new XChatApi({
    accessToken: "expired",
    refreshToken: "refresh-1",
    clientId: "client-id",
    clientSecret: "client-secret",
    clientFactory,
    tokenStore: { get: () => null, set: (tokens) => stored.push(tokens) },
    fetchImpl: async (_url, options) => {
      assert.equal(options.method, "POST")
      assert.match(options.headers.authorization, /^Basic /)
      return {
        ok: true,
        json: async () => ({ access_token: "fresh", refresh_token: "refresh-2", expires_in: 3600 }),
      }
    },
  })

  await api.listConversations()
  assert.deepEqual(createdTokens, ["expired", "fresh"])
  assert.equal(stored[0].access_token, "fresh")
  assert.equal(stored[0].refresh_token, "refresh-2")
})

test("refreshes the current Juicebox identity through the official public-key endpoint", async () => {
  let requestedFields
  const api = new XChatApi({
    client: {
      users: {
        getPublicKey: async (_userId, options) => {
          requestedFields = options.publicKeyFields
          return {
            data: [{
              publicKeyVersion: "7",
              publicKey: "identity",
              signingPublicKey: "signing",
              identityPublicKeySignature: "signature",
              juiceboxConfig: { token_map: [] },
            }],
          }
        },
      },
    },
  })

  assert.deepEqual(await api.getIdentity("self", "7"), {
    identity: {
      user_id: "self",
      public_key_version: "7",
      juicebox_config: { token_map: [] },
    },
    signing_keys: [{
      user_id: "self",
      public_key_version: "7",
      public_key: "identity",
      signing_public_key: "signing",
      identity_public_key_signature: "signature",
    }],
  })
  assert.equal(requestedFields.includes("juicebox_config"), true)
})

test("paces official XChat public-key reads", async () => {
  let now = 1000
  const sleeps = []
  const calls = []
  const api = new XChatApi({
    publicKeyReadSpacingMs: 900,
    now: () => now,
    sleepImpl: async (delayMs) => {
      sleeps.push(delayMs)
      now += delayMs
    },
    client: {
      users: {
        getPublicKey: async (userId) => {
          calls.push({ userId, at: now })
          return { data: [{
            publicKeyVersion: "1",
            publicKey: "identity",
            signingPublicKey: "signing",
            identityPublicKeySignature: "signature",
          }] }
        },
      },
    },
  })

  await Promise.all([api.getSigningKeys("one"), api.getSigningKeys("two")])
  assert.deepEqual(sleeps, [900])
  assert.deepEqual(calls, [{ userId: "one", at: 1000 }, { userId: "two", at: 1900 }])
})

test("reuses one sender signing-key read for a rate-limit window", async () => {
  let calls = 0
  const api = new XChatApi({
    client: {
      users: {
        getPublicKey: async () => {
          calls += 1
          return { data: [{
            publicKeyVersion: "1",
            publicKey: "identity",
            signingPublicKey: "signing",
            identityPublicKeySignature: "signature",
          }] }
        },
      },
    },
  })

  assert.deepEqual(await api.getSigningKeys("sender"), await api.getSigningKeys("sender"))
  assert.equal(calls, 1)
})
