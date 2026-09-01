export async function startXChatWorkers({ cache, pending, sync }) {
  await cache.prepareDecryption()
  pending.request()
  sync.resumeIncompleteJobs()
}

export function xchatStartupRetryDelay(error, now = Date.now) {
  const headers = error?.headers ?? error?.response?.headers
  const value = (name) => headers?.get?.(name) ?? headers?.[name] ?? headers?.[name.replaceAll("-", "_")]
  const retryAfterSeconds = Number(value("retry-after"))
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) return (retryAfterSeconds * 1000) + 250
  const resetAtMs = Number(value("x-rate-limit-reset")) * 1000
  if (Number.isFinite(resetAtMs) && resetAtMs > now()) return (resetAtMs - now()) + 1000
  return Number(error?.status ?? error?.response?.status) === 429 ? 15 * 60 * 1000 : 60 * 1000
}
