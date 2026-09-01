const defaultRetryDelayMs = 15 * 60 * 1000

function headerValue(error, name) {
  const headers = error?.headers ?? error?.response?.headers
  return headers?.get?.(name) ?? headers?.[name] ?? headers?.[name.replaceAll("-", "_")]
}

function retryDelay(error, fallbackDelayMs, now, consecutiveFailures) {
  const retryAfterSeconds = Number(headerValue(error, "retry-after"))
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
    return Math.max(1000, (retryAfterSeconds * 1000) + 250)
  }
  const remaining = Number(headerValue(error, "x-rate-limit-remaining"))
  if (Number.isFinite(remaining) && remaining > 0 && consecutiveFailures <= 3) {
    return Math.min(60_000, 1000 * (2 ** Math.min(consecutiveFailures, 6)))
  }
  const reset = headerValue(error, "x-rate-limit-reset")
  const resetAtMs = Number(reset) * 1000
  if (!Number.isFinite(resetAtMs) || resetAtMs <= now()) return fallbackDelayMs
  return Math.max(1000, resetAtMs - now() + 1000)
}

function rateLimitDiagnostics(error) {
  const resetAtMs = Number(headerValue(error, "x-rate-limit-reset")) * 1000
  const retryAfterSeconds = Number(headerValue(error, "retry-after"))
  const safeText = (value) => typeof value === "string"
    ? value
      .replace(/https?:\/\/\S+/gi, "[url]")
      .replace(/\b\d{8,}\b/g, "[redacted]")
      .replace(/[A-Za-z0-9_=-]{32,}/g, "[redacted]")
      .slice(0, 300)
    : null
  return {
    rate_limit: Number(headerValue(error, "x-rate-limit-limit")) || null,
    rate_limit_remaining: Number(headerValue(error, "x-rate-limit-remaining")) || 0,
    rate_limit_reset_at: Number.isFinite(resetAtMs) && resetAtMs > 0
      ? new Date(resetAtMs).toISOString()
      : null,
    retry_after_ms: Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
      ? retryAfterSeconds * 1000
      : null,
    error_type: safeText(error?.data?.type),
    error_title: safeText(error?.data?.title),
    error_detail: safeText(error?.data?.detail),
  }
}

export class XChatPendingProcessor {
  #cache
  #consecutiveFailures = 0
  #lastDiagnostic = null
  #now
  #requested = false
  #retryDelayMs
  #retryNotBefore = 0
  #running = null
  #scheduleTask
  #timer = null

  constructor({
    cache,
    scheduleTask = (callback, delayMs) => {
      const timer = setTimeout(callback, delayMs)
      timer.unref()
      return timer
    },
    retryDelayMs = defaultRetryDelayMs,
    now = Date.now,
  }) {
    this.#cache = cache
    this.#scheduleTask = scheduleTask
    this.#retryDelayMs = retryDelayMs
    this.#now = now
  }

  get diagnostics() {
    return this.#lastDiagnostic
  }

  request() {
    this.#requested = true
    this.#schedule()
  }

  #report(event, fields = {}) {
    this.#lastDiagnostic = { event, ...fields, recorded_at: new Date(this.#now()).toISOString() }
  }

  #schedule() {
    if (this.#running || this.#timer) return
    const delayMs = Math.max(0, this.#retryNotBefore - this.#now())
    this.#timer = this.#scheduleTask(() => {
      this.#timer = null
      void this.#run()
    }, delayMs) ?? true
    if (delayMs > 0) {
      this.#lastDiagnostic = {
        ...this.#lastDiagnostic,
        event: "retry_scheduled",
        retry_at: new Date(this.#now() + delayMs).toISOString(),
        recorded_at: new Date(this.#now()).toISOString(),
      }
    } else {
      this.#report("processing_scheduled", { retry_at: null })
    }
  }

  async #run() {
    if (this.#running) return
    this.#requested = false
    this.#report("processing_started")
    this.#running = this.#cache.processPending({ limit: 1000 })
    try {
      const result = await this.#running
      this.#consecutiveFailures = 0
      this.#retryNotBefore = 0
      this.#report("processing_completed", {
        selected: result.selected,
        processed: result.processed,
        failed: result.failed,
      })
      if (result.selected >= 1000) this.#requested = true
    } catch (error) {
      this.#consecutiveFailures += 1
      const delayMs = retryDelay(error, this.#retryDelayMs, this.#now, this.#consecutiveFailures)
      this.#retryNotBefore = this.#now() + delayMs
      this.#requested = true
      this.#report("processing_failed", {
        status: Number(error?.status ?? error?.response?.status) || null,
        retry_at: new Date(this.#retryNotBefore).toISOString(),
        ...rateLimitDiagnostics(error),
      })
    } finally {
      this.#running = null
      if (this.#requested) this.#schedule()
    }
  }
}
