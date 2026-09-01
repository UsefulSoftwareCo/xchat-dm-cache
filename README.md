# Executor State Handler

A small authenticated JSON state service for Executor tools.

It also exposes an XChat batch decryptor backed by the official
`@xdevplatform/chat-xdk` WASM package and Juicebox PIN recovery. Set
`XCHAT_PIN` in Railway. The PIN is never accepted through an API route.

The service can keep an encrypted, durable XChat cache. Historical pages and
live webhook deliveries use the same idempotent ingestion path. The cache
stores ciphertext before it acknowledges a webhook. It applies conversation
key changes before it decrypts dependent messages. It encrypts the private
identity, OAuth tokens, and decrypted message objects at rest. Set a dedicated
`XCHAT_CACHE_ENCRYPTION_KEY` for this data.

## Routes

- `GET /health`
- `GET /openapi.json`
- `GET /state/{namespace}`
- `GET /state/{namespace}/{key}`
- `PUT /state/{namespace}/{key}` with `{ "value": ... }`
- `DELETE /state/{namespace}/{key}`
- `POST /xchat/decrypt-events`
- `POST /xchat/cache/configure`
- `POST /xchat/cache/signing-keys`
- `POST /xchat/cache/backfill`
- `POST /xchat/cache/process`
- `GET /xchat/cache/messages`
- `GET /xchat/cache/events`
- `GET /xchat/cache/conversations`
- `GET /xchat/cache/status`
- `POST /xchat/cache/backfill-jobs`
- `GET /xchat/cache/backfill-jobs`
- `GET /xchat/cache/backfill-jobs/{job_id}`
- `POST /xchat/cache/backfill-jobs/{job_id}`
- `GET /xchat/webhook` for X CRC checks
- `POST /xchat/webhook` for signed X activity events

Set `STATE_API_KEY`. Set `STATE_FILE` to a persistent volume path in production.
Set `XCHAT_CACHE_FILE` to override the SQLite path. Its default is
`xchat-cache.sqlite` beside `STATE_FILE`. Set `X_WEBHOOK_CONSUMER_SECRET` to the
consumer secret for the X app that owns the webhook. The webhook route rejects
unsigned or invalid requests.

For unattended history sync, set `X_OAUTH2_ACCESS_TOKEN`,
`X_OAUTH2_REFRESH_TOKEN`, and `X_OAUTH2_CLIENT_ID`. Set
`X_OAUTH2_CLIENT_SECRET` for a confidential OAuth client. The service encrypts
rotated OAuth tokens in SQLite. Each backfill job requires explicit event and
page limits. It checkpoints every page and resumes incomplete jobs after a
restart.

Webhook ingestion accepts `chat.received`, `chat.sent`, and
`chat.conversation_join`. It deduplicates deliveries by their exact body and
events by `event_uuid`. Backfill events use their event ID or a SHA-256 digest
when an event ID is not available. Decrypted messages use the signed message ID
when the XDK provides it.

The events route keeps all XDK event types. This includes messages, edits,
reactions, deletes, receipts, group changes, and settings changes. The messages
route returns only message events.
