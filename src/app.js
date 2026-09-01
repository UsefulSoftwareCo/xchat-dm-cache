import { timingSafeEqual } from "node:crypto"
import { verifyWebhookSignature, webhookCrcResponse } from "./xchat-cache.js"

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const maximumBodyBytes = 8 * 1024 * 1024

function json(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  })
  response.end(JSON.stringify(body))
}

function isAuthorized(request, apiKey) {
  const value = request.headers.authorization
  if (!value?.startsWith("Bearer ")) return false
  const supplied = Buffer.from(value.slice(7))
  const expected = Buffer.from(apiKey)
  return supplied.length === expected.length && timingSafeEqual(supplied, expected)
}

async function readBody(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > maximumBodyBytes) {
      const error = new Error("Request body exceeds 8 MiB")
      error.status = 413
      throw error
    }
    chunks.push(chunk)
  }
  if (size === 0) throw new Error("Request body is required")
  return Buffer.concat(chunks)
}

async function readJson(request) {
  return JSON.parse((await readBody(request)).toString("utf8"))
}

function cacheUnavailable(response) {
  return json(response, 503, { error: "XChat cache is not available" })
}

export function createHandler({ store, apiKey, publicBaseUrl, xchat, xchatCache, xchatSync, webhookSecret }) {
  if (!apiKey) throw new Error("STATE_API_KEY is required")

  return async function handler(request, response) {
    try {
      const url = new URL(request.url, "http://localhost")

      if (request.method === "GET" && url.pathname === "/health") {
        return json(response, 200, {
          ok: true,
          xchat_configured: xchat?.configured ?? false,
          xchat_cache_ready: Boolean(xchatCache),
          xchat_webhook_configured: Boolean(webhookSecret),
        })
      }

      if (request.method === "GET" && url.pathname === "/openapi.json") {
        return json(response, 200, openApiDocument(publicBaseUrl))
      }

      if (request.method === "GET" && url.pathname === "/xchat/webhook") {
        if (!webhookSecret) return json(response, 503, { error: "X webhook is not configured" })
        const crcToken = url.searchParams.get("crc_token")
        if (!crcToken) return json(response, 400, { error: "crc_token is required" })
        return json(response, 200, { response_token: webhookCrcResponse(crcToken, webhookSecret) })
      }

      if (request.method === "POST" && url.pathname === "/xchat/webhook") {
        if (!xchatCache || !webhookSecret) return cacheUnavailable(response)
        const rawBody = await readBody(request)
        const signature = request.headers["x-twitter-webhooks-signature"]
        if (!verifyWebhookSignature(rawBody, signature, webhookSecret)) {
          return json(response, 401, { error: "Invalid webhook signature" })
        }
        const result = xchatCache.acceptWebhook(JSON.parse(rawBody.toString("utf8")), rawBody)
        queueMicrotask(() => {
          xchatCache.processPending().catch((error) => console.error("XChat webhook processing failed", error))
        })
        return json(response, 200, result)
      }

      if (!isAuthorized(request, apiKey)) {
        response.setHeader("www-authenticate", "Bearer")
        return json(response, 401, { error: "Unauthorized" })
      }

      if (request.method === "POST" && url.pathname === "/xchat/decrypt-events") {
        if (!xchat) return json(response, 503, { error: "XChat is not available" })
        const body = await readJson(request)
        return json(response, 200, await xchat.decrypt(body))
      }

      if (url.pathname === "/xchat/cache/configure" && request.method === "POST") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.configure(await readJson(request)))
      }

      if (url.pathname === "/xchat/cache/signing-keys" && request.method === "POST") {
        if (!xchatCache) return cacheUnavailable(response)
        const body = await readJson(request)
        return json(response, 200, xchatCache.addSigningKeys(body.signing_keys))
      }

      if (url.pathname === "/xchat/cache/backfill" && request.method === "POST") {
        if (!xchatCache) return cacheUnavailable(response)
        const result = xchatCache.ingestBackfill(await readJson(request))
        const processing = await xchatCache.processPending({ limit: 1000 })
        return json(response, 200, { ...result, processing })
      }

      if (url.pathname === "/xchat/cache/process" && request.method === "POST") {
        if (!xchatCache) return cacheUnavailable(response)
        const body = await readJson(request).catch(() => ({}))
        return json(response, 200, await xchatCache.processPending({ limit: body.limit }))
      }

      if (url.pathname === "/xchat/cache/messages" && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.listMessages({
          limit: url.searchParams.get("limit"),
          before: url.searchParams.get("before") || undefined,
          after: url.searchParams.get("after") || undefined,
          conversation_id: url.searchParams.get("conversation_id") || undefined,
          direction: url.searchParams.get("direction") || undefined,
        }))
      }

      if (url.pathname === "/xchat/cache/events" && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.listEvents({
          limit: url.searchParams.get("limit"),
          before: url.searchParams.get("before") || undefined,
          after: url.searchParams.get("after") || undefined,
          conversation_id: url.searchParams.get("conversation_id") || undefined,
          direction: url.searchParams.get("direction") || undefined,
          event_type: url.searchParams.get("event_type") || undefined,
        }))
      }

      if (url.pathname === "/xchat/cache/conversations" && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.listConversations({ limit: url.searchParams.get("limit") }))
      }

      if (url.pathname === "/xchat/cache/status" && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.status())
      }

      if (url.pathname === "/xchat/cache/backfill-jobs" && request.method === "POST") {
        if (!xchatCache || !xchatSync) return cacheUnavailable(response)
        const job = xchatSync.createJob(await readJson(request))
        xchatSync.schedule(job.id)
        return json(response, 202, job)
      }

      if (url.pathname === "/xchat/cache/backfill-jobs" && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        return json(response, 200, xchatCache.listBackfillJobs({ limit: url.searchParams.get("limit") }))
      }

      const backfillJobMatch = url.pathname.match(/^\/xchat\/cache\/backfill-jobs\/([^/]+)$/)
      if (backfillJobMatch && request.method === "GET") {
        if (!xchatCache) return cacheUnavailable(response)
        const job = xchatCache.getBackfillJob(decodeURIComponent(backfillJobMatch[1]))
        return job ? json(response, 200, job) : json(response, 404, { error: "XChat backfill job was not found" })
      }

      if (backfillJobMatch && request.method === "POST") {
        if (!xchatSync) return cacheUnavailable(response)
        const job = await xchatSync.runJob(decodeURIComponent(backfillJobMatch[1]))
        return json(response, 200, job)
      }

      if (backfillJobMatch && request.method === "PATCH") {
        if (!xchatCache || !xchatSync) return cacheUnavailable(response)
        const job = xchatCache.raiseBackfillJobLimits(decodeURIComponent(backfillJobMatch[1]), await readJson(request))
        if (!job) return json(response, 404, { error: "XChat backfill job was not found" })
        xchatSync.schedule(job.id)
        return json(response, 200, job)
      }

      const segments = url.pathname.split("/").filter(Boolean).map(decodeURIComponent)
      if (segments[0] !== "state" || segments.length < 2 || segments.length > 3) {
        return json(response, 404, { error: "Not found" })
      }

      const [, namespace, key] = segments
      if (![namespace, key].filter(Boolean).every((value) => identifierPattern.test(value))) {
        return json(response, 400, { error: "Invalid namespace or key" })
      }

      if (request.method === "GET" && segments.length === 2) {
        return json(response, 200, { keys: store.list(namespace) })
      }

      if (request.method === "GET") {
        const value = store.get(namespace, key)
        return value === undefined
          ? json(response, 404, { error: "State value not found" })
          : json(response, 200, { namespace, key, value })
      }

      if (request.method === "PUT") {
        const body = await readJson(request)
        if (!("value" in body)) return json(response, 400, { error: "value is required" })
        await store.set(namespace, key, body.value)
        return json(response, 200, { namespace, key, value: body.value })
      }

      if (request.method === "DELETE") {
        const deleted = await store.delete(namespace, key)
        return deleted
          ? json(response, 200, { deleted: true })
          : json(response, 404, { error: "State value not found" })
      }

      response.setHeader("allow", "GET, PUT, DELETE")
      return json(response, 405, { error: "Method not allowed" })
    } catch (error) {
      const status = error?.status ?? (error instanceof SyntaxError ? 400 : 500)
      return json(response, status, { error: status === 500 ? "Internal server error" : error.message })
    }
  }
}

export function openApiDocument(publicBaseUrl) {
  const valueSchema = {}
  const identitySchema = {
    type: "object",
    required: ["user_id", "public_key_version", "juicebox_config"],
    properties: {
      user_id: { type: "string" },
      public_key_version: { type: "string" },
      juicebox_config: { type: "object", additionalProperties: true },
    },
  }
  const signingKeySchema = {
    type: "object",
    required: ["user_id", "public_key_version", "public_key", "signing_public_key", "identity_public_key_signature"],
    properties: {
      user_id: { type: "string" },
      public_key_version: { type: "string" },
      public_key: { type: "string" },
      signing_public_key: { type: "string" },
      identity_public_key_signature: { type: "string" },
    },
  }
  const conversationSchema = {
    type: "object",
    required: ["id"],
    properties: {
      id: { type: "string" },
      type: { type: "string" },
      participant_ids: { type: "array", items: { type: "string" }, default: [] },
    },
  }
  const errorResponses = {
    "401": { description: "Missing or invalid bearer token" },
    "404": { description: "State value not found" },
  }
  const parameters = [
    { name: "namespace", in: "path", required: true, schema: { type: "string" } },
    { name: "key", in: "path", required: true, schema: { type: "string" } },
  ]

  return {
    openapi: "3.1.0",
    info: { title: "Executor State Handler", version: "0.3.0" },
    ...(publicBaseUrl ? { servers: [{ url: publicBaseUrl }] } : {}),
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
      schemas: {
        StateValue: {
          type: "object",
          required: ["namespace", "key", "value"],
          properties: { namespace: { type: "string" }, key: { type: "string" }, value: valueSchema },
        },
      },
    },
    security: [{ bearerAuth: [] }],
    paths: {
      "/xchat/decrypt-events": {
        post: {
          operationId: "decryptXChatEvents",
          summary: "Decrypt an XChat event batch with the configured Juicebox identity",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["identity", "signing_keys", "events"],
                  properties: {
                    identity: identitySchema,
                    signing_keys: {
                      type: "array",
                      minItems: 1,
                      items: signingKeySchema,
                    },
                    key_events: { type: "array", items: { type: "string" }, default: [] },
                    events: { type: "array", items: { type: "string" } },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Decrypted XChat messages and per-event errors", content: { "application/json": { schema: {} } } },
            "400": { description: "Invalid event batch" },
            "401": errorResponses["401"],
            "503": { description: "XChat PIN is not configured" },
          },
        },
      },
      "/xchat/cache/configure": {
        post: {
          operationId: "configureXChatCache",
          summary: "Configure the private XChat cache identity and public signing keys",
          requestBody: {
            required: true,
            content: { "application/json": { schema: {
              type: "object",
              required: ["identity", "signing_keys"],
              properties: {
                identity: identitySchema,
                signing_keys: { type: "array", items: signingKeySchema },
                conversations: { type: "array", items: conversationSchema, default: [] },
              },
            } } },
          },
          responses: { "200": { description: "Cache configuration summary" }, "400": { description: "Invalid configuration" }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/signing-keys": {
        post: {
          operationId: "addXChatSigningKeys",
          summary: "Add or update cached XChat public signing keys",
          requestBody: {
            required: true,
            content: { "application/json": { schema: {
              type: "object",
              required: ["signing_keys"],
              properties: { signing_keys: { type: "array", minItems: 1, items: signingKeySchema } },
            } } },
          },
          responses: { "200": { description: "Stored key count" }, "400": { description: "Invalid keys" }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/backfill": {
        post: {
          operationId: "ingestXChatBackfillPage",
          summary: "Ingest and decrypt one historical XChat event page idempotently",
          requestBody: {
            required: true,
            content: { "application/json": { schema: {
              type: "object",
              required: ["conversation", "events"],
              properties: {
                conversation: conversationSchema,
                identity: identitySchema,
                signing_keys: { type: "array", items: signingKeySchema, default: [] },
                key_events: { type: "array", items: { type: "string" }, default: [] },
                events: { type: "array", items: {
                  type: "object",
                  required: ["encoded_event"],
                  properties: {
                    event_uuid: { type: "string" },
                    event_type: { type: "string" },
                    id: { type: "string" },
                    conversation_id: { type: "string" },
                    sender_id: { type: "string" },
                    encoded_event: { type: "string" },
                    created_at: { type: "string", format: "date-time" },
                  },
                } },
              },
            } } },
          },
          responses: { "200": { description: "Ingestion and processing counts" }, "400": { description: "Invalid page" }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/process": {
        post: {
          operationId: "processPendingXChatEvents",
          summary: "Retry pending XChat cache events",
          requestBody: { content: { "application/json": { schema: {
            type: "object",
            properties: { limit: { type: "integer", minimum: 1, maximum: 1000, default: 100 } },
          } } } },
          responses: { "200": { description: "Processing counts" }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/messages": {
        get: {
          operationId: "listCachedXChatMessages",
          summary: "List decrypted messages from the private XChat cache",
          parameters: [
            { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 50 } },
            { name: "before", in: "query", schema: { type: "string", format: "date-time" } },
            { name: "after", in: "query", schema: { type: "string", format: "date-time" } },
            { name: "conversation_id", in: "query", schema: { type: "string" } },
            { name: "direction", in: "query", schema: { type: "string", enum: ["sent", "received"] } },
          ],
          responses: { "200": { description: "Cached decrypted messages", content: { "application/json": { schema: {} } } }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/events": {
        get: {
          operationId: "listCachedXChatEvents",
          summary: "List all decrypted XChat events from the private cache",
          parameters: [
            { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 50 } },
            { name: "before", in: "query", schema: { type: "string", format: "date-time" } },
            { name: "after", in: "query", schema: { type: "string", format: "date-time" } },
            { name: "conversation_id", in: "query", schema: { type: "string" } },
            { name: "direction", in: "query", schema: { type: "string", enum: ["sent", "received"] } },
            { name: "event_type", in: "query", schema: { type: "string" } },
          ],
          responses: { "200": { description: "Cached decrypted XChat events", content: { "application/json": { schema: {} } } }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/conversations": {
        get: {
          operationId: "listCachedXChatConversations",
          summary: "List XChat cache conversation summaries",
          parameters: [{ name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 50 } }],
          responses: { "200": { description: "Cached conversation summaries", content: { "application/json": { schema: {} } } }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/status": {
        get: {
          operationId: "getXChatCacheStatus",
          summary: "Get private XChat cache counts and readiness",
          responses: { "200": { description: "Cache status", content: { "application/json": { schema: {} } } }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/backfill-jobs": {
        post: {
          operationId: "createXChatBackfillJob",
          summary: "Create a resumable bounded XChat archive backfill",
          requestBody: { required: true, content: { "application/json": { schema: {
            type: "object",
            required: ["max_events", "max_pages"],
            properties: {
              max_events: { type: "integer", minimum: 1, description: "Hard event-read limit for this job" },
              max_pages: { type: "integer", minimum: 1, description: "Hard API page limit for this job" },
            },
          } } } },
          responses: { "202": { description: "Durable backfill job created" }, "400": { description: "Invalid limits" }, "401": errorResponses["401"], "503": { description: "X OAuth is not configured" } },
        },
        get: {
          operationId: "listXChatBackfillJobs",
          summary: "List durable XChat archive backfill jobs",
          parameters: [{ name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 20 } }],
          responses: { "200": { description: "Backfill jobs" }, "401": errorResponses["401"] },
        },
      },
      "/xchat/cache/backfill-jobs/{job_id}": {
        get: {
          operationId: "getXChatBackfillJob",
          summary: "Get a durable XChat archive backfill job",
          parameters: [{ name: "job_id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: { "200": { description: "Backfill job" }, "401": errorResponses["401"], "404": { description: "Backfill job not found" } },
        },
        post: {
          operationId: "runXChatBackfillJob",
          summary: "Resume one durable XChat archive backfill job",
          parameters: [{ name: "job_id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: { "200": { description: "Current backfill job state" }, "401": errorResponses["401"], "404": { description: "Backfill job not found" } },
        },
        patch: {
          operationId: "raiseXChatBackfillJobLimits",
          summary: "Raise the limits for one durable XChat backfill job",
          parameters: [{ name: "job_id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          requestBody: { required: true, content: { "application/json": { schema: {
            type: "object",
            properties: {
              max_events: { type: "integer", minimum: 1, description: "New event-read limit; it cannot lower the current limit" },
              max_pages: { type: "integer", minimum: 1, description: "New API page limit; it cannot lower the current limit" },
            },
            minProperties: 1,
          } } } },
          responses: { "200": { description: "Updated backfill job" }, "400": { description: "Invalid limits" }, "401": errorResponses["401"], "404": { description: "Backfill job not found" } },
        },
      },
      "/state/{namespace}": {
        get: {
          operationId: "listStateKeys",
          summary: "List keys in a namespace",
          parameters: parameters.slice(0, 1),
          responses: { "200": { description: "Keys", content: { "application/json": { schema: { type: "object", required: ["keys"], properties: { keys: { type: "array", items: { type: "string" } } } } } } }, "401": errorResponses["401"] },
        },
      },
      "/state/{namespace}/{key}": {
        get: {
          operationId: "getStateValue",
          summary: "Read a state value",
          parameters,
          responses: { "200": { description: "State value", content: { "application/json": { schema: { $ref: "#/components/schemas/StateValue" } } } }, ...errorResponses },
        },
        put: {
          operationId: "putStateValue",
          summary: "Create or replace a state value",
          parameters,
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["value"], properties: { value: valueSchema } } } } },
          responses: { "200": { description: "Stored state value", content: { "application/json": { schema: { $ref: "#/components/schemas/StateValue" } } } }, "401": errorResponses["401"] },
        },
        delete: {
          operationId: "deleteStateValue",
          summary: "Delete a state value",
          parameters,
          responses: { "200": { description: "Deletion result", content: { "application/json": { schema: { type: "object", required: ["deleted"], properties: { deleted: { type: "boolean" } } } } } }, ...errorResponses },
        },
      },
    },
  }
}
