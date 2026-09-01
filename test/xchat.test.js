import assert from "node:assert/strict"
import { test } from "node:test"
import { XChatDecryptor } from "../src/xchat.js"

test("uses the official SDK session contract and reuses the unlocked session", async () => {
  const calls = []
  const chat = {
    unlock: async (pin) => calls.push(["unlock", pin]),
    setIdentity: (...args) => calls.push(["identity", ...args]),
    setCacheKeys: (enabled) => calls.push(["cache", enabled]),
    setSigningKeys: (keys) => calls.push(["signing", keys]),
    decryptEvents: (events) => ({ messages: events.map((event) => ({ event })) }),
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
  })
  await decryptor.decrypt(body)

  assert.deepEqual(calls.slice(0, 4), [
    ["create", "realm-token"],
    ["unlock", "safe-pin"],
    ["identity", "10", "20"],
    ["cache", true],
  ])
  assert.equal(calls.filter(([name]) => name === "create").length, 1)
  assert.deepEqual(calls.at(-1)[1][0], {
    userId: "10",
    publicKeyVersion: "20",
    publicKey: "signing-key",
    identityPublicKey: "identity-key",
    identityPublicKeySignature: "signature",
  })
})

test("fails closed when the PIN is not configured", async () => {
  const decryptor = new XChatDecryptor({ createChat: async () => ({}), pin: "" })
  await assert.rejects(() => decryptor.decrypt({}), /PIN is not configured/)
})
