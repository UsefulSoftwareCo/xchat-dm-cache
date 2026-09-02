import assert from "node:assert/strict"
import { test } from "node:test"
import { searchMessagePages } from "../src/message-search.js"

const messages = [
  { id: "3", text: "Let us INVEST in Executor" },
  { id: "2", text: "Executor only" },
  { id: "1", text: "invest elsewhere" },
]

function listPage({ before, limit }) {
  const offset = before ? Number(before) : 0
  const data = messages.slice(offset, offset + limit)
  return { data, meta: { next_before: offset + data.length < messages.length ? String(offset + data.length) : null } }
}

test("searches message pages with normalized case-insensitive terms", () => {
  const result = searchMessagePages({ listPage, textOf: (message) => message.text, options: { query: "executor INVEST", limit: 10 } })
  assert.deepEqual(result.data.map((message) => message.id), ["3"])
  assert.equal(result.meta.scanned_count, 3)
  assert.equal(result.meta.truncated, false)
})

test("bounds scans and rejects empty queries", () => {
  const result = searchMessagePages({ listPage, textOf: (message) => message.text, options: { query: "missing", scan_limit: 2 } })
  assert.equal(result.meta.scanned_count, 2)
  assert.equal(result.meta.truncated, true)
  assert.throws(() => searchMessagePages({ listPage, textOf: (message) => message.text, options: { query: "  " } }), /query must contain text/)
})
