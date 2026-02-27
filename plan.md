# Mindgame Development Plan

Go. Vendored dependencies. Idiomatic code. Tests where they earn their keep.

## Phase 1 — Skeleton

Get a proxy that starts, accepts connections, and forwards HTTP traffic. No MITM yet.

**Deliverables:**
- `go mod init`, dependencies vendored (`go mod vendor`)
- Project structure:
  ```
  cmd/mindgame/       main.go — flag parsing, wiring, startup
  internal/proxy/     HTTP proxy handler (CONNECT + plain HTTP forwarding)
  internal/db/        SQLite database layer (schema creation, queries)
  internal/ca/        CA generation and certificate signing
  ```
- SQLite database initialization — create tables on first run (`audit_log`, `domain_rules`, `scoring_rules`)
- Plain HTTP forward proxy (no TLS interception) — accepts requests, forwards them, returns responses
- CONNECT handling — accept CONNECT, tunnel bytes bidirectionally (passthrough, no interception yet)
- Audit logging of every request (method, url, host, timestamp, action=ALLOW)
- Basic integration test: start proxy, make HTTP request through it, verify it arrives and is logged

**Key dependency:** `github.com/mattn/go-sqlite3` (CGo) or `modernc.org/sqlite` (pure Go, simpler build). Pure Go is probably better for portability — no CGo toolchain needed.

## Phase 2 — TLS Interception

The hard part. MITM the CONNECT tunnels.

**Deliverables:**
- CA generation on first run (`ca.pem`, `ca.key`) — RSA or ECDSA key pair, self-signed root certificate
- On-the-fly certificate minting — given a hostname, generate a leaf cert signed by the CA, cache it in memory
- CONNECT interception — instead of blind tunneling, hijack the connection, TLS handshake with client using minted cert, open separate TLS connection to target
- Decrypted request/response capture — read the plaintext HTTP inside the tunnel, log full headers and bodies
- X-Reason header enforcement on all requests (reject with 400 if missing)
- Tests: verify CA generation, verify cert minting for a domain, integration test with a TLS client trusting the CA

## Phase 3 — Domain Policy

Three-tier routing: allow, deny, default.

**Deliverables:**
- `domain_rules` table seeded from config file (`-seed` flag)
- Domain lookup on every request (deny-first evaluation)
- Deny tier: respond 403, log with action=DENY, close connection
- Allow tier: forward without requiring X-Reason, log with action=ALLOW
- Default tier: require X-Reason, forward if present, reject 400 if missing
- Domain rule caching in memory with invalidation (reload from DB periodically or on-demand)
- Tests: deny blocks, allow passes without header, default requires header

## Phase 4 — Risk Scoring with CEL

Score every request. Act on the score for default-tier traffic.

**Deliverables:**
- `github.com/google/cel-go` integration
- CEL environment setup with request variables (`method`, `url`, `host`, `path`, `body`, `body_size`, `headers`, `reason`)
- `scoring_rules` table with default rules seeded on first run
- Score evaluation: run all enabled rules against each request, sum points
- Score thresholds for default-tier traffic: 0–9 forward, 10–19 block, 20+ block and ban
- Dynamic bans: insert deny rule with `banned=true` on score 20+
- `risk_score` and `risk_signals` written to audit log for every request
- Tests: CEL expression evaluation, score accumulation, ban insertion, verify allowed-tier traffic isn't blocked regardless of score

## Phase 5 — Web UI (Dashboard)

Operational interface for humans.

**Deliverables:**
- `templ` templates, HTMX for interactivity
- Static assets (HTMX JS, CSS) embedded via `go:embed`
- UI HTTP server on separate port (`-ui-port` flag)
- **Live Feed page** (`/`) — SSE endpoint streaming audit log entries, table with color-coded rows, click-to-expand detail, filters (action, host, score, time range)
- **Domain Rules page** (`/domains`) — list, add, edit, delete domain rules, ban review (banned entries sorted to top)
- **Scoring Rules page** (`/scoring`) — list, toggle, edit, add rules. Test mode: submit a sample request, see which rules fire
- **Statistics page** (`/stats`) — requests/minute, top hosts, recent bans, rule hit frequency
- Navigation between pages (simple top nav bar)
- No tests for templates themselves — test the HTTP handlers and SSE logic

## Phase 6 — Dream Mode

The ambient visualization.

**Deliverables:**
- `/dream` route serving a self-contained HTML page
- Canvas-based particle system driven by the SSE feed
- Visual encoding: size=body size, color=risk score, motion=action type
- Host lanes, fading text, ban flares
- Full-screen, no chrome, Escape to exit
- No automated tests — this is visual and subjective

## Dependency Summary

| Package | Purpose |
|---|---|
| `modernc.org/sqlite` | SQLite driver, pure Go |
| `github.com/google/cel-go` | CEL expression evaluation |
| `github.com/a-h/templ` | Type-safe HTML templates |

HTMX is a single JS file, embedded. No other frontend dependencies.

## What's Deliberately Out of Scope

- Authentication on the web UI (assume trusted network / add later)
- Proxy authentication (agents don't authenticate to the proxy)
- WebSocket proxying (HTTP/HTTPS only)
- HTTP/2 interception (HTTP/1.1 inside the tunnel is fine for now)
- Retention policy / log rotation
- Clustering / multi-instance
