# API v1

Login: `POST /api/v1/auth/login` with email/password. Subsequent browser calls use the session cookie. Mutation calls include `X-CSRF-Token` from the login response. `auth/me`, `auth/refresh`, `auth/logout` manage sessions. No public account creation exists; admins use `POST admin-users`.

Agents use `Authorization: Bearer TOKEN` and `X-Agent-ID: UUID`. Paths are scoped to `agents` or `probes`:

| Method | Path | Purpose |
|---|---|---|
| POST | `enrollment-tokens` | Admin creates expiring one-use token; optional existing `vps_id` rotates credentials |
| POST | `{kind}/enroll` | Exchange token/name/region/provider for identity credentials |
| POST | `{kind}/heartbeat` | Bounded health/version/IP update |
| GET | `{kind}/config` | Agent protocol compatibility or Probe targets/controls |
| POST | `agents/events/batch` | Aggregated connection events |
| POST | `agents/traffic/batch` | User/node traffic intervals |
| POST | `probes/results/batch` | Probe evidence |

Batch envelope: `batch_id`, nonnegative `sequence`, `schema_version` (1 or 2), numeric `created_at`, and `events`. Body may be gzip. A successful committed response includes `accepted: true` and the exact `batch_id`. Retry network errors/503/429 with backoff; do not delete on an unexpected response. Duplicate identical batches succeed without extra rows. 409 means ID/content conflict. 422 means invalid data. Agent-supplied VPS IDs are not accepted: central binds data to the authenticated identity.

Read APIs: `vps`, `vps/{id}`, `events`, `events/summary`, `search?q=`, `traffic`, `probe-results`, `block-events`, `block-events/{id}`, `correlation/{users|source-ips|domains|destination-ips|nodes}`, `{users|source-ips|domains|destination-ips}/{key}/activity`, and `entities/{entity}/{key}`. IPs in path segments must be URL-encoded.

Lists use `page_number` (1-based), `size` (1–200), `items` and `has_more`. Time-filtered APIs use RFC3339 `start`/`end`, default 24 hours, maximum 31 days. Search matches exact user/node IDs, normalized IPs, domain, VPS name or VPS ID. Correlation filters include `event_id` and `key`.

Admins can `PATCH vps/{id}`, create `probe-targets`, revoke `DELETE identities/{id}`, create manual `POST block-events`, request `POST block-events/{id}/recalculate`, edit `PATCH settings`, and retrieve bounded `GET export?start=...&end=...`. `GET admin-audit-log` lists sensitive action history.

Operational paths: `/healthz`, `/readyz`, authenticated `/metrics`, `/api/v1/system/health`, `/api/v1/system/metrics`. A live process can be healthy while the database is not ready. Do not use HTTP 200 from `/healthz` as proof of successful ingest.
