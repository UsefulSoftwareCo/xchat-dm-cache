# Executor State Handler

A small authenticated JSON state service for Executor tools.

## Routes

- `GET /health`
- `GET /openapi.json`
- `GET /state/{namespace}`
- `GET /state/{namespace}/{key}`
- `PUT /state/{namespace}/{key}` with `{ "value": ... }`
- `DELETE /state/{namespace}/{key}`

Set `STATE_API_KEY`. Set `STATE_FILE` to a persistent volume path in production.
