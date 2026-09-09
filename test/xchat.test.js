import assert from "node:assert/strict"
import { test } from "node:test"
import { XChatDecryptor } from "../src/xchat.js"

test("prepares the official SDK session without decrypting events", async () => {
  const calls = []
  const decryptor = new XChatDecryptor({
    pin: "safe-pin",
    createChat: async () => ({
      unlock: async () => calls.push("unlock"),
      setIdentity: () => calls.push("identity"),
      setCacheKeys: () => calls.push("cache"),
      decryptEvents: () => calls.push("decrypt"),
    }),
  })
  assert.deepEqual(await decryptor.prepare({
    user_id: "10",
    public_key_version: "20",
    juicebox_config: {},
  }), { ready: true })
  assert.deepEqual(calls, ["unlock", "identity", "cache"])
})

test("uses the official SDK session contract and reuses the unlocked session", async () => {
  const calls = []
  const chat = {
    unlock: async (pin) => calls.push(["unlock", pin]),
    setIdentity: (...args) => calls.push(["identity", ...args]),
    setCacheKeys: (enabled) => calls.push(["cache", enabled]),
    setSigningKeys: (keys) => calls.push(["signing", keys]),
    decryptEvents: (events) => {
      calls.push(["decrypt", events])
      return { messages: events.map((event) => ({ event })), errors: {} }
    },
  }
  const decryptor = new XChatDecryptor({
    pin: "safe-pin",
    createChat: async (options) => {
      calls.push(["create", await options.getAuthToken("realm-1")])
      return chat
    },
  })
  const body = {
    identity: {
      user_id: "10",
      public_key_version: "20",
      juicebox_config: { token_map: [{ key: "realm-1", value: { token: "realm-token" } }] },
    },
    signing_keys: [{
      user_id: "10",
      public_key_version: "20",
      public_key: "identity-key",
      signing_public_key: "signing-key",
      identity_public_key_signature: "signature",
    }],
    key_events: ["key-event"],
    events: ["message-event"],
  }

  assert.deepEqual(await decryptor.decrypt(body), {
    messages: [{ event: "key-event" }, { event: "message-event" }],
    errors: {},
  })
  await decryptor.decrypt(body)

  assert.deepEqual(calls.slice(0, 4), [
    ["create", "realm-token"],
    ["unlock", "safe-pin"],
    ["identity", "10", "20"],
    ["cache", true],
  ])
  assert.equal(calls.filter(([name]) => name === "create").length, 1)
  assert.equal(calls.filter(([name]) => name === "signing").length, 1)
  assert.deepEqual(calls.find(([name]) => name === "signing")[1][0], {
    userId: "10",
    publicKeyVersion: "20",
    publicKey: "signing-key",
    identityPublicKey: "identity-key",
    identityPublicKeySignature: "signature",
  })
  assert.deepEqual(calls.filter(([name]) => name === "decrypt").map(([, events]) => events), [
    ["key-event", "message-event"],
    ["key-event", "message-event"],
  ])
})

test("replays changed conversation keys and reinstalls changed signing keys", async () => {
  const calls = []
  const chat = {
    unlock: async () => {},
    setIdentity: () => {},
    setCacheKeys: () => {},
    setSigningKeys: (keys) => calls.push(["signing", keys]),
    decryptEvents: (events) => {
      calls.push(["decrypt", events])
      return { messages: [], errors: {} }
    },
  }
  const decryptor = new XChatDecryptor({ pin: "safe-pin", createChat: async () => chat })
  const body = {
    identity: { user_id: "10", public_key_version: "20", juicebox_config: {} },
    signing_keys: [{
      user_id: "10",
      public_key_version: "20",
      public_key: "identity-key",
      signing_public_key: "signing-key",
      identity_public_key_signature: "signature",
    }],
    key_events: ["key-1"],
    events: ["message-1"],
  }

  await decryptor.decrypt(body)
  await decryptor.decrypt({ ...body, key_events: ["key-1", "key-2"], events: ["message-2"] })
  await decryptor.decrypt({
    ...body,
    signing_keys: [{ ...body.signing_keys[0], signing_public_key: "signing-key-2" }],
    events: ["message-3"],
  })

  assert.equal(calls.filter(([name]) => name === "signing").length, 2)
  assert.deepEqual(calls.filter(([name]) => name === "decrypt").map(([, events]) => events), [
    ["key-1", "message-1"],
    ["key-1", "key-2", "message-2"],
    ["key-1", "message-3"],
  ])
})

test("supplies historical keys on later batches when the SDK only caches the newest version", async () => {
  const decryptor = new XChatDecryptor({
    pin: "test-pin",
    createChat: async () => ({
      unlock: async () => {}, setIdentity() {}, setCacheKeys() {}, setSigningKeys() {},
      decryptEvents: (events) => events.includes("old-key-version")
        ? { messages: [{ originalB64: events.at(-1), event: { type: "message" } }], errors: {} }
        : { messages: [], errors: { "0": "Historical key version is not in the SDK cache" } },
    }),
  })
  const body = {
    identity: { user_id: "self", public_key_version: "1", juicebox_config: {} },
    signing_keys: [{ user_id: "sender", public_key_version: "1", public_key: "identity", signing_public_key: "signing", identity_public_key_signature: "signature" }],
    key_events: ["old-key-version", "new-key-version"],
    events: ["old-reply-1"],
  }
  await decryptor.decrypt(body)
  const result = await decryptor.decrypt({ ...body, events: ["old-reply-2"] })
  assert.deepEqual(result.errors, {})
  assert.equal(result.messages[0].originalB64, "old-reply-2")
})

test("fails closed when the PIN is not configured", async () => {
  const decryptor = new XChatDecryptor({ createChat: async () => ({}), pin: "" })
  await assert.rejects(() => decryptor.decrypt({}), /PIN is not configured/)
})

test("reports count-only decryption diagnostics", async () => {
  const diagnostics = []
  const decryptor = new XChatDecryptor({
    pin: "safe-pin",
    diagnostic: (event, fields) => diagnostics.push({ event, ...fields }),
    createChat: async () => ({
      unlock: async () => {},
      setIdentity: () => {},
      setCacheKeys: () => {},
      setSigningKeys: () => {},
      decryptEvents: () => ({ messages: [], errors: { 0: "invalid" } }),
    }),
  })

  await decryptor.decrypt({
    identity: { user_id: "10", public_key_version: "20", juicebox_config: {} },
    signing_keys: [{
      user_id: "10",
      public_key_version: "20",
      public_key: "identity-key",
      signing_public_key: "signing-key",
      identity_public_key_signature: "signature",
    }],
    key_events: ["secret-key-event"],
    events: ["secret-message-event"],
  })

  assert.deepEqual(diagnostics.map(({ event }) => event), [
    "session_unlock_started",
    "session_unlock_completed",
    "decrypt_started",
    "decrypt_completed",
  ])
  assert.equal(diagnostics.at(-1).key_event_count, 1)
  assert.equal(diagnostics.at(-1).event_count, 1)
  assert.equal(diagnostics.at(-1).error_count, 1)
  assert.equal(JSON.stringify(diagnostics).includes("secret"), false)
  assert.equal(decryptor.diagnostics.event, "decrypt_completed")
  assert.equal(decryptor.diagnostics.key_event_count, 1)
  assert.equal(typeof decryptor.diagnostics.recorded_at, "string")
  assert.equal(JSON.stringify(decryptor.diagnostics).includes("secret"), false)
})

test("redacts credentials and URLs from failure diagnostics", async () => {
  const decryptor = new XChatDecryptor({
    pin: "safe-pin",
    createChat: async () => ({
      unlock: async () => {
        throw new Error("request https://realm.example/token?secret=abc failed for abcdefghijklmnopqrstuvwxyz1234567890")
      },
    }),
  })

  await assert.rejects(() => decryptor.decrypt({
    identity: { user_id: "10", public_key_version: "20", juicebox_config: {} },
    signing_keys: [{
      user_id: "10",
      public_key_version: "20",
      public_key: "identity-key",
      signing_public_key: "signing-key",
      identity_public_key_signature: "signature",
    }],
    events: ["event"],
  }))

  assert.equal(decryptor.diagnostics.event, "session_unlock_failed")
  assert.equal(decryptor.diagnostics.error_message, "request [url] failed for [redacted]")
})

test("refreshes an expired official Juicebox identity once", async () => {
  const createdConfigs = []
  const refreshes = []
  const decryptor = new XChatDecryptor({
    pin: "safe-pin",
    refreshIdentity: async (identity) => {
      refreshes.push(identity)
      return {
        user_id: identity.userId,
        public_key_version: identity.publicKeyVersion,
        juicebox_config: { token_map: [{ key: "realm", value: { token: "fresh" } }] },
      }
    },
    createChat: async ({ juiceboxConfig }) => {
      createdConfigs.push(JSON.parse(juiceboxConfig))
      const fresh = juiceboxConfig.includes("fresh")
      return {
        unlock: async () => {
          if (!fresh) throw new Error("Juicebox recovery failed: reason=InvalidAuth")
        },
        setIdentity: () => {},
        setCacheKeys: () => {},
        setSigningKeys: () => {},
        decryptEvents: () => ({ messages: [], errors: {} }),
      }
    },
  })

  const result = await decryptor.decrypt({
    identity: {
      user_id: "10",
      public_key_version: "20",
      juicebox_config: { token_map: [{ key: "realm", value: { token: "expired" } }] },
    },
    signing_keys: [{
      user_id: "10",
      public_key_version: "20",
      public_key: "identity-key",
      signing_public_key: "signing-key",
      identity_public_key_signature: "signature",
    }],
    events: ["event"],
  })

  assert.deepEqual(result, { messages: [], errors: {} })
  assert.deepEqual(refreshes, [{ userId: "10", publicKeyVersion: "20" }])
  assert.equal(createdConfigs.length, 2)
  assert.equal(createdConfigs[1].token_map[0].value.token, "fresh")
})
