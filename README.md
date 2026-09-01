# Executor State Handler

A small authenticated JSON state service for Executor tools.

It also exposes an XChat batch decryptor backed by the official
`@xdevplatform/chat-xdk` WASM package and Juicebox PIN recovery. Set
`XCHAT_PIN` in Railway. The PIN is never accepted through an API route.

## Routes

- `GET /health`
- `GET /openapi.json`
- `GET /state/{namespace}`
- `GET /state/{namespace}/{key}`
- `PUT /state/{namespace}/{key}` with `{ "value": ... }`
- `DELETE /state/{namespace}/{key}`
- `POST /xchat/decrypt-events`

Set `STATE_API_KEY`. Set `STATE_FILE` to a persistent volume path in production.
