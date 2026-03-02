# Mindgame

MITM audit proxy for AI agents. Intercepts HTTPS traffic, enforces intent declarations, and scores requests for risk.

## What It Does

Mindgame sits between your AI agent and the internet. It decrypts TLS traffic, requires agents to state why they're making each request via an `X-Reason` header, and logs everything to SQLite.

Domains are classified into three tiers:

- Allow — trusted, e.g. model APIs. Forwarded without requiring `X-Reason`.
- Deny — blocked outright.
- Default — everything else. Requires `X-Reason`. Scored for risk.

Risk scoring uses CEL expressions. Requests scoring 10+ are blocked. Requests scoring 20+ ban the host until a human reviews it.

## Quick Start

### Docker

```bash
docker run -p 2080:2080 -p 2180:2180 -v mindgame-data:/data ghcr.io/perbu/mindgame
```

### From source

```
go build ./cmd/mindgame
./mindgame -addr :2080 -db audit.db -ui-addr :2180
```

First run generates `ca.pem` and `ca.key`. Agents can fetch the CA certificate directly from the proxy:

```bash
curl http://localhost:2080/ca.pem -o ca.pem
```

Add the CA to your agent's trust store:

```bash
# Node.js
export NODE_EXTRA_CA_CERTS=./ca.pem

# Python
export REQUESTS_CA_BUNDLE=./ca.pem

# System — Debian/Ubuntu
cp ca.pem /usr/local/share/ca-certificates/mindgame.crt && update-ca-certificates
```

Point the agent at the proxy:

```bash
export http_proxy=http://localhost:2080
export https_proxy=http://localhost:2080
```

Seed domain rules from a file:

```
./mindgame -seed domains.conf -db audit.db
```

## Domain Configuration

```
allow api.anthropic.com
allow api.openai.com
deny evil.example.com
```

Rules are stored in SQLite and editable via the web UI at `http://localhost:2180/domains`.

Allowlist your LLM provider, e.g. `api.anthropic.com` or `api.openai.com`. Without an allow rule, model API calls will all be logged and scored, filling up your audit database with uninteresting traffic.

## Scoring Rules

Risk scoring uses [CEL](https://github.com/google/cel-spec) expressions stored in the database. Default rules flag sensitive paths, credential patterns, confidential keywords, and large outbound payloads. Add, edit, or disable rules via the web UI at `http://localhost:2180/scoring`.

## Web UI

`http://localhost:2180`

- Live Feed — real-time request stream via SSE, filterable by action/host/score. Rejected and denied requests show a human-readable status reason explaining why.
- Domain Rules — manage allow/deny list, review bans
- Scoring Rules — edit CEL expressions, test rules against sample requests
- Statistics — request rates, top hosts, rule hit frequency
- Dream Mode at `/dream` — ambient full-screen visualization for NOC displays

## Querying the Audit Log directly

```sql
-- Recent blocked requests
SELECT timestamp, host, url, reason, risk_score, risk_signals
FROM audit_log WHERE action IN ('BLOCK', 'BAN') ORDER BY timestamp DESC LIMIT 20;

-- Hosts with highest average risk
SELECT host, AVG(risk_score) as avg_score, COUNT(*) as requests
FROM audit_log GROUP BY host ORDER BY avg_score DESC;

-- All requests from a specific agent session
SELECT * FROM audit_log WHERE reason LIKE '%task-id-1234%';
```

## Recommendations

### Certificates

Pre-generate your CA certificate and key and store them outside the container. If the proxy regenerates its CA on each restart, you'll need to redistribute the certificate to every agent. Mount the cert directory into the container instead:

```bash
# Generate certs once
./mindgame -addr :0 &  # starts and creates ca.pem + ca.key, then stop it
# Or run the container once and copy the certs out

docker run -p 2080:2080 -p 2180:2180 \
  -v /path/to/certs:/certs \
  -v mindgame-data:/data \
  ghcr.io/perbu/mindgame -ca-cert /certs/ca.pem -ca-key /certs/ca.key
```

### Agent image

If your agent is something like [OpenClaw](https://github.com/openclaw), consider building the CA certificate and proxy configuration directly into the agent's Docker image. This avoids runtime setup and ensures the agent always trusts the proxy.

### WebSocket and SSE

WebSocket and Server-Sent Events (SSE) connections will **not** function through the proxy. This is by design — Mindgame is a request/response audit proxy. Any services your agent depends on that use WebSocket or SSE should be added to the allow list, which bypasses the proxy's interception.

### Allow-listing

At a minimum, allow-list:

- **LLM provider** — `api.anthropic.com`, `api.openai.com`, etc. These generate high-volume, low-risk traffic that will fill your audit log with noise.
- **Communication platforms** — Slack, Discord, WhatsApp, or whatever your agent uses to interact with users. These often rely on WebSocket/SSE.

### Injecting headers with external tools

Agents that shell out to tools like `gh` (GitHub CLI) won't automatically include the `X-Reason` header. Most CLI tools have options for injecting extra HTTP headers — for example, `gh` supports `--header`. Rather than relying on the agent to remember this, build wrapper scripts around these tools:

```bash
#!/bin/bash
# gh-wrapper: wraps gh with the required X-Reason header
if [ -z "$GH_REASON" ]; then
  echo "Error: GH_REASON is not set. Set it to a short description of why this request is being made." >&2
  echo "The Mindgame proxy requires an X-Reason header on all requests to non-allow-listed hosts." >&2
  exit 1
fi
exec gh "$@" --header "X-Reason: $GH_REASON"
```

This way the agent calls the wrapper instead of the tool directly, and the header is always included.

## License

MIT
