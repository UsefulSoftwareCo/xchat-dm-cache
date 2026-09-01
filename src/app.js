import { timingSafeEqual } from "node:crypto"

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const maximumBodyBytes = 1024 * 1024

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

async function readJson(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > maximumBodyBytes) {
      const error = new Error("Request body exceeds 1 MiB")
      error.status = 413
      throw error
    }
    chunks.push(chunk)
  }
  if (size === 0) throw new Error("Request body is required")
  return JSON.parse(Buffer.concat(chunks).toString("utf8"))
}

export function createHandler({ store, apiKey, publicBaseUrl }) {
  if (!apiKey) throw new Error("STATE_API_KEY is required")

  return async function handler(request, response) {
    try {
      const url = new URL(request.url, "http://localhost")

      if (request.method === "GET" && url.pathname === "/health") {
        return json(response, 200, { ok: true })
      }

      if (request.method === "GET" && url.pathname === "/openapi.json") {
        return json(response, 200, openApiDocument(publicBaseUrl))
      }

      if (!isAuthorized(request, apiKey)) {
        response.setHeader("www-authenticate", "Bearer")
        return json(response, 401, { error: "Unauthorized" })
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
    info: { title: "Executor State Handler", version: "0.1.0" },
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
