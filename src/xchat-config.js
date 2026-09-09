import { juiceboxClientConfig } from "@xdevplatform/chat-xdk"

export function validateJuiceboxConfig(value) {
  try {
    const unwrapped = juiceboxClientConfig(value)
    const config = typeof unwrapped === "string" ? JSON.parse(unwrapped) : unwrapped
    if (!Array.isArray(config?.realms) || config.realms.length === 0) throw new Error()
    if (config.realms.some((realm) => typeof realm.id !== "string" || typeof realm.address !== "string")) throw new Error()
    for (const field of ["register_threshold", "recover_threshold"]) {
      if (!Number.isInteger(config[field]) || config[field] < 1 || config[field] > config.realms.length) throw new Error()
    }
    if (typeof config.pin_hashing_mode !== "string") throw new Error()
  } catch {
    // Do not pass malformed configuration to the WASM constructor: it panics
    // and leaves the process-wide Juicebox runtime unusable on later retries.
    const error = new Error("XChat recovery configuration is invalid; refresh the identity")
    error.code = "INVALID_XCHAT_CONFIG"
    throw error
  }
}

export function juiceboxConfigFromXdk(value) {
  const config = {
    key_store_token_map_json: value.keyStoreTokenMapJson,
    max_guess_count: value.maxGuessCount,
    token_map: value.tokenMap,
  }
  validateJuiceboxConfig(config)
  return config
}
