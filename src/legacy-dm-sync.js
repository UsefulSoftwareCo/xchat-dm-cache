const maximumRequestsPerSlice = 10

export class LegacyDmSync {
  #api
  #cache
  #runningRecent = null
  #runningJobs = new Map()

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

  schedule(jobId) {
    setImmediate(() => {
      this.runJob(jobId).then((job) => {
        if (job && ["pending", "running"].includes(job.status)) this.schedule(jobId)
      }).catch(() => {})
    })
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
        const page = await this.#api.listLegacyDmEventsByParticipant(target.participant_id, {
          paginationToken: target.pagination_token,
          maxResults: Math.min(100, remainingEvents),
        })
        const ingestion = this.#cache.ingest({ events: page.events, users: page.users, source: "historical_backfill" })
        const complete = !page.next_token
        this.#cache.updateBackfillTarget(jobId, target.participant_id, {
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
