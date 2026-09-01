import assert from "node:assert/strict"
import { test } from "node:test"
import { XChatPendingProcessor } from "../src/xchat-pending.js"

test("coalesces requests and retries pending processing after a rate limit", async () => {
  let now = 1_700_000_000_000
  let calls = 0
  const scheduled = []
  const processor = new XChatPendingProcessor({
    cache: {
      processPending: async () => {
        calls += 1
        if (calls === 1) {
          const error = new Error("rate limited")
          error.status = 429
          error.headers = new Headers({
            "x-rate-limit-limit": "5",
            "x-rate-limit-remaining": "0",
            "x-rate-limit-reset": String((now + 900_000) / 1000),
          })
          error.data = { type: "https://api.x.com/problems/usage-capped" }
          throw error
        }
        return { selected: 2, processed: 2, failed: 0 }
      },
    },
    now: () => now,
    retryDelayMs: 900_000,
    scheduleTask: (callback, delayMs) => {
      scheduled.push({ callback, delayMs })
      return scheduled.length
    },
  })

  processor.request()
  processor.request()
  assert.equal(scheduled.length, 1)
  assert.equal(scheduled[0].delayMs, 0)

  scheduled.shift().callback()
  await new Promise(setImmediate)
  assert.equal(calls, 1)
  assert.equal(scheduled.length, 1)
  assert.equal(scheduled[0].delayMs, 901_000)
  assert.equal(processor.diagnostics.event, "retry_scheduled")
  assert.equal(processor.diagnostics.rate_limit, 5)
  assert.equal(processor.diagnostics.rate_limit_remaining, 0)
  assert.equal(processor.diagnostics.rate_limit_reset_at, "2023-11-14T22:28:20.000Z")
  assert.equal(processor.diagnostics.error_type, "https://api.x.com/problems/usage-capped")

  processor.request()
  assert.equal(scheduled.length, 1)
  now += 901_000
  scheduled.shift().callback()
  await new Promise(setImmediate)

  assert.equal(calls, 2)
  assert.equal(processor.diagnostics.event, "processing_completed")
  assert.equal(processor.diagnostics.processed, 2)
})
