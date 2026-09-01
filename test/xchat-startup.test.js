import assert from "node:assert/strict"
import { test } from "node:test"
import { startXChatWorkers, xchatStartupRetryDelay } from "../src/xchat-startup.js"

test("unlocks XChat before starting queue and archive workers", async () => {
  const calls = []
  await startXChatWorkers({
    cache: { prepareDecryption: async () => calls.push("prepare") },
    pending: { request: () => calls.push("pending") },
    sync: { resumeIncompleteJobs: () => calls.push("sync") },
  })
  assert.deepEqual(calls, ["prepare", "pending", "sync"])
})

test("does not consume archive quota when XChat unlock fails", async () => {
  const calls = []
  await assert.rejects(() => startXChatWorkers({
    cache: { prepareDecryption: async () => { throw new Error("unlock failed") } },
    pending: { request: () => calls.push("pending") },
    sync: { resumeIncompleteJobs: () => calls.push("sync") },
  }), /unlock failed/)
  assert.deepEqual(calls, [])
})

test("retries startup at the X rate-limit reset", () => {
  const error = new Error("rate limited")
  error.status = 429
  error.headers = new Headers({ "x-rate-limit-reset": "1700000030" })
  assert.equal(xchatStartupRetryDelay(error, () => 1700000000000), 31000)
})
