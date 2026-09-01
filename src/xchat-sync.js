const maximumRequestsPerSlice = 10
const rateLimitRetryDelayMs = 15 * 60 * 1000
const rateLimitRetryMessage = "X API rate limit reached; retry scheduled"

function isRateLimitError(error) {
  return Number(error?.status ?? error?.response?.status) === 429 || /\b429\b|too many requests|rate limit/i.test(String(error?.message ?? error))
}

function headerValue(error, name) {
  const headers = error?.headers ?? error?.response?.headers
  return headers?.get?.(name) ?? headers?.[name] ?? headers?.[name.replaceAll("-", "_")]
}

function rateLimitDelay(error, fallbackDelayMs, now) {
  const resetAtMs = Number(headerValue(error, "x-rate-limit-reset")) * 1000
  if (!Number.isFinite(resetAtMs) || resetAtMs <= 0) return fallbackDelayMs
  return Math.max(1000, resetAtMs - now() + 1000)
}

function rateLimitDiagnostics(error, retryDelayMs, nowMs) {
  const limitValue = headerValue(error, "x-rate-limit-limit")
  const remainingValue = headerValue(error, "x-rate-limit-remaining")
  const resetValue = headerValue(error, "x-rate-limit-reset")
  const limit = limitValue == null ? Number.NaN : Number(limitValue)
  const remaining = remainingValue == null ? Number.NaN : Number(remainingValue)
  const resetAtMs = resetValue == null ? Number.NaN : Number(resetValue) * 1000
  return {
    rate_limit: Number.isFinite(limit) ? limit : null,
    rate_limit_remaining: Number.isFinite(remaining) ? remaining : null,
    rate_limit_reset_at: Number.isFinite(resetAtMs) && resetAtMs > 0 ? new Date(resetAtMs).toISOString() : null,
    retry_at: new Date(nowMs + retryDelayMs).toISOString(),
  }
}

export class XChatSync {
  #api
  #cache
  #lastDiagnostic = null
  #pendingProcessor
  #running = new Map()
  #scheduled = new Set()
  #scheduleTask
  #rateLimitRetryDelayMs
  #now

  constructor({
    api,
    cache,
    pendingProcessor,
    scheduleTask = (callback, delayMs) => delayMs > 0 ? setTimeout(callback, delayMs) : setImmediate(callback),
    rateLimitDelayMs = rateLimitRetryDelayMs,
    now = Date.now,
  }) {
    this.#api = api
    this.#cache = cache
    this.#pendingProcessor = pendingProcessor
    this.#scheduleTask = scheduleTask
    this.#rateLimitRetryDelayMs = rateLimitDelayMs
    this.#now = now
  }

  get configured() {
    return this.#api.configured
  }

  get diagnostics() {
    return this.#lastDiagnostic
  }

  #report(event, fields = {}) {
    this.#lastDiagnostic = { event, ...fields, recorded_at: new Date().toISOString() }
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

  schedule(jobId, delayMs = 0) {
    if (this.#scheduled.has(jobId)) return
    this.#scheduled.add(jobId)
    this.#scheduleTask(() => {
      this.#scheduled.delete(jobId)
      this.runJob(jobId).then((job) => {
        if (!job || !["pending", "running"].includes(job.status)) return
        const nextDelayMs = job.last_error === rateLimitRetryMessage ? this.#rateLimitRetryDelayMs : 0
        this.schedule(jobId, nextDelayMs)
      }).catch(() => {})
    }, delayMs)
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
      if (isRateLimitError(error)) {
        const retryDelayMs = rateLimitDelay(error, this.#rateLimitRetryDelayMs, this.#now)
        const nowMs = this.#now()
        this.#report("conversation_event_read_failed", {
          status: 429,
          ...rateLimitDiagnostics(error, retryDelayMs, nowMs),
        })
        const job = this.#cache.updateBackfillJob(jobId, {
          status: "pending",
          last_error: rateLimitRetryMessage,
        })
        this.schedule(jobId, retryDelayMs)
        return job
      }
      return this.#cache.updateBackfillJob(jobId, {
        status: "failed",
        last_error: String(error?.message ?? error).slice(0, 500),
      })
    }
  }

  async #fetchConversationPage(job) {
    this.#report("conversation_list_started")
    let page
    try {
      page = await this.#api.listConversations({ paginationToken: job.conversation_cursor, maxResults: 100 })
    } catch (error) {
      this.#report("conversation_list_failed", { status: Number(error?.status ?? error?.response?.status) || null })
      throw error
    }
    this.#report("conversation_list_completed", { conversation_count: page.data.length })
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
    const remainingEvents = Math.max(1, job.max_events - job.events_seen)
    this.#report("conversation_event_read_started")
    let page
    try {
      page = await this.#api.listConversationEvents(conversation.conversation_id, {
        paginationToken: conversation.event_cursor,
        maxResults: Math.min(100, remainingEvents),
      })
    } catch (error) {
      this.#report("conversation_event_read_failed", { status: Number(error?.status ?? error?.response?.status) || null })
      throw error
    }
    this.#report("conversation_event_read_completed", { event_count: page.events.length })
    const ingestion = this.#cache.ingestBackfill({
      conversation: {
        id: conversation.conversation_id,
        type: conversation.type,
        participant_ids: participantIds,
      },
      key_events: page.key_events,
      events: page.events,
    })
    this.#pendingProcessor?.request()
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
