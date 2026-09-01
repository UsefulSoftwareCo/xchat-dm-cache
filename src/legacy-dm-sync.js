const maximumRequestsPerSlice = 10
const retryableStatuses = new Set([408, 425, 429, 500, 502, 503, 504])
const unavailableTargetStatuses = new Set([400, 403, 404, 410])

function statusOf(error) {
  return Number(error?.status ?? error?.response?.status) || null
}

function retryDelayMs(error) {
  const headers = error?.headers ?? error?.response?.headers
  const retryAfter = Number(headers?.get?.("retry-after") ?? headers?.["retry-after"])
  if (Number.isFinite(retryAfter) && retryAfter > 0) return Math.min(retryAfter * 1000, 15 * 60 * 1000)
  const resetAt = Number(headers?.get?.("x-rate-limit-reset") ?? headers?.["x-rate-limit-reset"])
  if (Number.isFinite(resetAt) && resetAt > 0) return Math.min(Math.max(1_000, (resetAt * 1000) - Date.now()), 15 * 60 * 1000)
  return statusOf(error) === 429 ? 60_000 : 15_000
}

export class LegacyDmSync {
  #api
  #cache
  #runningRecent = null
  #runningJobs = new Map()
  #retryDelays = new Map()

  constructor({ api, cache }) {
    this.#api = api
    this.#cache = cache
  }

  get configured() {
    return this.#api.configured
  }

  async ensureConfigured() {
    if (this.#cache.status().configured) return
    const user = await this.#api.getMe()
    this.#cache.configure({ self_id: user.id })
  }

  syncRecent({ maxPages = 5 } = {}) {
    if (this.#runningRecent) return this.#runningRecent
    this.#runningRecent = this.#syncRecent(maxPages).finally(() => {
      this.#runningRecent = null
    })
    return this.#runningRecent
  }

  async #syncRecent(maxPages) {
    await this.ensureConfigured()
    let paginationToken
    let pages = 0
    let seen = 0
    let inserted = 0
    try {
      do {
        const page = await this.#api.listLegacyDmEvents({ paginationToken, maxResults: 100 })
        const result = this.#cache.ingest({ events: page.events, users: page.users, source: "recent_poll" })
        pages += 1
        seen += page.events.length
        inserted += result.inserted
        paginationToken = page.next_token
      } while (paginationToken && pages < Math.max(1, Number(maxPages) || 1))
      this.#cache.setConfig("last_recent_sync_at", new Date().toISOString())
      this.#cache.setConfig("last_recent_sync_error", null)
      return { pages, seen, inserted, complete: !paginationToken }
    } catch (error) {
      this.#cache.setConfig("last_recent_sync_error", String(error?.message ?? error).slice(0, 500))
      throw error
    }
  }

  createJob(options) {
    if (!this.configured) {
      const error = new Error("X OAuth 2.0 user access token is not configured")
      error.status = 503
      throw error
    }
    return this.#cache.createBackfillJob(options)
  }

  runJob(jobId, { requestLimit = maximumRequestsPerSlice } = {}) {
    if (this.#runningJobs.has(jobId)) return this.#runningJobs.get(jobId)
    const promise = this.#runJob(jobId, requestLimit).finally(() => this.#runningJobs.delete(jobId))
    this.#runningJobs.set(jobId, promise)
    return promise
  }

  schedule(jobId, delayMs = 0) {
    const run = () => {
      this.runJob(jobId).then((job) => {
        if (job && ["pending", "running"].includes(job.status)) {
          this.schedule(jobId, this.#retryDelays.get(jobId) ?? 0)
        }
      }).catch(() => {})
    }
    if (delayMs > 0) setTimeout(run, delayMs).unref()
    else setImmediate(run)
  }

  resumeIncompleteJobs() {
    for (const job of this.#cache.listBackfillJobs({ limit: 100 }).data) {
      if (["pending", "running"].includes(job.status)) this.schedule(job.id)
    }
  }

  async #runJob(jobId, requestLimit) {
    await this.ensureConfigured()
    let job = this.#cache.getBackfillJob(jobId)
    if (!job) {
      const error = new Error("Legacy DM backfill job was not found")
      error.status = 404
      throw error
    }
    if (["completed", "paused"].includes(job.status)) return job
    this.#cache.updateBackfillJob(jobId, { status: "running", last_error: null })
    try {
      for (let index = 0; index < requestLimit; index += 1) {
        job = this.#cache.getBackfillJob(jobId)
        if (job.pages_fetched >= job.max_pages || job.events_seen >= job.max_events) {
          return this.#cache.updateBackfillJob(jobId, { status: "paused", last_error: "Configured backfill limit reached" })
        }
        const target = this.#cache.nextBackfillTarget(jobId)
        if (!target) return this.#cache.updateBackfillJob(jobId, { status: "completed", last_error: null })
        const remainingEvents = Math.max(1, job.max_events - job.events_seen)
        let page
        try {
          const options = { paginationToken: target.pagination_token, maxResults: Math.min(100, remainingEvents) }
          page = target.target_type === "conversation"
            ? await this.#api.listLegacyDmEventsByConversation(target.target_id, options)
            : await this.#api.listLegacyDmEventsByParticipant(target.target_id, options)
          this.#retryDelays.delete(jobId)
        } catch (error) {
          const status = statusOf(error)
          if (unavailableTargetStatuses.has(status)) {
            this.#cache.updateBackfillTarget(jobId, target.target_type, target.target_id, {
              status: "failed",
              pages_fetched: target.pages_fetched + 1,
              last_error: `X API returned ${status}`,
            })
            this.#cache.updateBackfillJob(jobId, { pages_fetched: job.pages_fetched + 1 })
            continue
          }
          if (retryableStatuses.has(status) || status === null) {
            this.#retryDelays.set(jobId, retryDelayMs(error))
            return this.#cache.updateBackfillJob(jobId, {
              status: "pending",
              last_error: status ? `X API temporarily returned ${status}` : "Temporary X API request failure",
            })
          }
          throw error
        }
        const ingestion = this.#cache.ingest({ events: page.events, users: page.users, source: "historical_backfill" })
        const complete = !page.next_token
        this.#cache.updateBackfillTarget(jobId, target.target_type, target.target_id, {
          status: complete ? "completed" : "running",
          pagination_token: page.next_token,
          pages_fetched: target.pages_fetched + 1,
          events_seen: target.events_seen + page.events.length,
          last_error: null,
        })
        this.#cache.updateBackfillJob(jobId, {
          pages_fetched: job.pages_fetched + 1,
          events_seen: job.events_seen + page.events.length,
          unique_events: job.unique_events + ingestion.inserted,
        })
      }
      return this.#cache.getBackfillJob(jobId)
    } catch (error) {
      return this.#cache.updateBackfillJob(jobId, {
        status: "failed",
        last_error: String(error?.message ?? error).slice(0, 500),
      })
    }
  }
}
