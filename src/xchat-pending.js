const defaultRetryDelayMs = 15 * 60 * 1000

function retryDelay(error, fallbackDelayMs, now) {
  const headers = error?.headers ?? error?.response?.headers
  const reset = headers?.get?.("x-rate-limit-reset")
    ?? headers?.["x-rate-limit-reset"]
    ?? headers?.["X-Rate-Limit-Reset"]
  const resetAtMs = Number(reset) * 1000
  if (!Number.isFinite(resetAtMs) || resetAtMs <= now()) return fallbackDelayMs
  return Math.max(1000, resetAtMs - now() + 1000)
}

function rateLimitDiagnostics(error) {
  const headers = error?.headers ?? error?.response?.headers
  const readHeader = (name) => headers?.get?.(name) ?? headers?.[name] ?? headers?.[name.replaceAll("-", "_")]
  const resetAtMs = Number(readHeader("x-rate-limit-reset")) * 1000
  return {
    rate_limit: Number(readHeader("x-rate-limit-limit")) || null,
    rate_limit_remaining: Number(readHeader("x-rate-limit-remaining")) || 0,
    rate_limit_reset_at: Number.isFinite(resetAtMs) && resetAtMs > 0
      ? new Date(resetAtMs).toISOString()
      : null,
    error_type: typeof error?.data?.type === "string"
      ? error.data.type.slice(0, 200)
      : typeof error?.data?.title === "string"
        ? error.data.title.slice(0, 200)
        : null,
  }
}

export class XChatPendingProcessor {
  #cache
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
      this.#retryNotBefore = 0
      this.#report("processing_completed", {
        selected: result.selected,
        processed: result.processed,
        failed: result.failed,
      })
    } catch (error) {
      const delayMs = retryDelay(error, this.#retryDelayMs, this.#now)
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
