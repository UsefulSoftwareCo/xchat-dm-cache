const maximumRequestsPerSlice = 10

export class XChatSync {
  #api
  #cache
  #running = new Map()

  constructor({ api, cache }) {
    this.#api = api
    this.#cache = cache
  }

  get configured() {
    return this.#api.configured
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
    if (this.#running.has(jobId)) return this.#running.get(jobId)
    const promise = this.#runJob(jobId, requestLimit).finally(() => this.#running.delete(jobId))
    this.#running.set(jobId, promise)
    return promise
  }

  resumeIncompleteJobs() {
    for (const job of this.#cache.listBackfillJobs({ limit: 100 }).data) {
      if (["pending", "running"].includes(job.status)) this.schedule(job.id)
    }
  }

  schedule(jobId) {
    setImmediate(() => {
      this.runJob(jobId).then((job) => {
        if (job && ["pending", "running"].includes(job.status)) this.schedule(jobId)
      }).catch(() => {})
    })
  }

  async #runJob(jobId, requestLimit) {
    let job = this.#cache.getBackfillJob(jobId)
    if (!job) {
      const error = new Error("XChat backfill job was not found")
      error.status = 404
      throw error
    }
    if (["completed", "paused"].includes(job.status)) return job
    if (job.pages_fetched >= job.max_pages || job.events_seen >= job.max_events) {
      return this.#cache.updateBackfillJob(jobId, { status: "paused", last_error: "Configured backfill limit reached" })
    }

    this.#cache.updateBackfillJob(jobId, { status: "running", last_error: null })
    try {
      for (let requestCount = 0; requestCount < requestLimit; requestCount += 1) {
        job = this.#cache.getBackfillJob(jobId)
        if (job.pages_fetched >= job.max_pages || job.events_seen >= job.max_events) {
          return this.#cache.updateBackfillJob(jobId, { status: "paused", last_error: "Configured backfill limit reached" })
        }
        if (job.stage === "conversations") await this.#fetchConversationPage(job)
        else if (job.stage === "events") await this.#fetchEventPage(job)
        else return this.#cache.updateBackfillJob(jobId, { status: "completed", last_error: null })
      }
      return this.#cache.getBackfillJob(jobId)
    } catch (error) {
      return this.#cache.updateBackfillJob(jobId, {
        status: "failed",
        last_error: String(error?.message ?? error).slice(0, 500),
      })
    }
  }

  async #fetchConversationPage(job) {
    const page = await this.#api.listConversations({ paginationToken: job.conversation_cursor, maxResults: 100 })
    this.#cache.addBackfillJobConversations(job.id, page.data)
    this.#cache.updateBackfillJob(job.id, {
      pages_fetched: job.pages_fetched + 1,
      conversation_cursor: page.next_token,
      stage: page.has_more && page.next_token ? "conversations" : "events",
    })
  }

  async #fetchEventPage(job) {
    const conversation = this.#cache.nextBackfillConversation(job.id)
    if (!conversation) {
      this.#cache.updateBackfillJob(job.id, { stage: "complete", status: "completed", last_error: null })
      return
    }
    const participantIds = JSON.parse(conversation.participant_ids_json)
    for (const participantId of participantIds) {
      const keys = await this.#api.getSigningKeys(participantId)
      if (keys.length > 0) this.#cache.addSigningKeys(keys)
    }
    const remainingEvents = Math.max(1, job.max_events - job.events_seen)
    const page = await this.#api.listConversationEvents(conversation.conversation_id, {
      paginationToken: conversation.event_cursor,
      maxResults: Math.min(100, remainingEvents),
    })
    const ingestion = this.#cache.ingestBackfill({
      conversation: {
        id: conversation.conversation_id,
        type: conversation.type,
        participant_ids: participantIds,
      },
      key_events: page.key_events,
      events: page.events,
    })
    await this.#cache.processPending({ limit: 1000 })
    const conversationComplete = !page.has_more || !page.next_token
    this.#cache.updateBackfillConversation(job.id, conversation.conversation_id, {
      status: conversationComplete ? "completed" : "running",
      event_cursor: page.next_token,
      pages_fetched: conversation.pages_fetched + 1,
      events_seen: conversation.events_seen + page.events.length,
      last_error: null,
    })
    this.#cache.updateBackfillJob(job.id, {
      pages_fetched: job.pages_fetched + 1,
      events_seen: job.events_seen + page.events.length,
      unique_events: job.unique_events + ingestion.inserted,
    })
  }
}
