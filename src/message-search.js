function boundedInteger(value, fallback, maximum) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback
}

function normalizedTerms(query) {
  if (typeof query !== "string" || query.trim().length === 0) {
    const error = new Error("query must contain text")
    error.status = 400
    throw error
  }
  if (query.length > 512) {
    const error = new Error("query must be at most 512 characters")
    error.status = 400
    throw error
  }
  return query.normalize("NFKC").toLocaleLowerCase().trim().split(/\s+/u)
}

export function searchMessagePages({ listPage, textOf, options = {} }) {
  const terms = normalizedTerms(options.query)
  const limit = boundedInteger(options.limit, 50, 100)
  const scanLimit = boundedInteger(options.scan_limit, 20_000, 100_000)
  const matches = []
  let before = options.before
  let scanned = 0
  let nextBefore = null

  while (scanned < scanLimit && matches.length < limit) {
    const page = listPage({ ...options, before, limit: Math.min(100, scanLimit - scanned) })
    for (const message of page.data) {
      scanned += 1
      const text = String(textOf(message) ?? "").normalize("NFKC").toLocaleLowerCase()
      if (terms.every((term) => text.includes(term))) matches.push(message)
      if (matches.length === limit || scanned === scanLimit) break
    }
    nextBefore = page.meta.next_before ?? null
    if (!nextBefore || page.data.length === 0 || nextBefore === before) break
    before = nextBefore
  }

  return {
    data: matches,
    meta: {
      result_count: matches.length,
      scanned_count: scanned,
      scan_limit: scanLimit,
      truncated: scanned === scanLimit && Boolean(nextBefore),
    },
  }
}
