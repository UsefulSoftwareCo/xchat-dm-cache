import assert from "node:assert/strict"
import { test } from "node:test"
import { juiceboxClientConfig } from "@xdevplatform/chat-xdk"
import { juiceboxConfigFromXdk, validateJuiceboxConfig } from "../src/xchat-config.js"
import { XChatDecryptor } from "../src/xchat.js"

const realms = JSON.stringify({
  realms: [{ id: "realm-1", address: "https://realm.example.test", public_key: "test-public-key" }],
  register_threshold: 1,
  recover_threshold: 1,
  pin_hashing_mode: "Standard2019",
})
const sdkConfig = {
  keyStoreTokenMapJson: realms,
  maxGuessCount: 20,
  tokenMap: [{ key: "realm-1", value: { address: "https://realm.example.test", token: "test-token" } }],
}

test("converts the X API SDK response into the Chat SDK wire format without altering embedded realm JSON", () => {
  const config = juiceboxConfigFromXdk(sdkConfig)
  assert.equal(juiceboxClientConfig(config), realms)
  assert.equal(config.max_guess_count, 20)
  assert.deepEqual(config.token_map, sdkConfig.tokenMap)
})

test("rejects malformed recovery configuration before it can reach WASM", () => {
  for (const config of [sdkConfig, {}, { key_store_token_map_json: "{" }, { key_store_token_map_json: "{}" }]) {
    assert.throws(() => validateJuiceboxConfig(config), { code: "INVALID_XCHAT_CONFIG" })
  }
})

test("refreshes a previously cached SDK-shaped identity before constructing a WASM session", async () => {
  const created = []
  let refreshes = 0
  const corrected = juiceboxConfigFromXdk(sdkConfig)
  const identity = { user_id: "self", public_key_version: "7", juicebox_config: sdkConfig }
  const decryptor = new XChatDecryptor({
    pin: "test-pin",
    createChat: (options) => {
      const config = JSON.parse(options.juiceboxConfig)
      validateJuiceboxConfig(config)
      created.push(config)
      return { unlock: async () => {}, setIdentity() {}, setCacheKeys() {} }
    },
    refreshIdentity: async () => {
      refreshes += 1
      return { ...identity, juicebox_config: corrected }
    },
  })
  assert.deepEqual(await decryptor.prepare(identity), { ready: true })
  assert.equal(refreshes, 1)
  assert.deepEqual(created, [corrected])
})
