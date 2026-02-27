# Mindgame

A specialized Man-in-the-Middle (MITM) audit proxy designed for AI agents and automated systems.

## The Concept

When granting an LLM agent or automated process access to the internet, traditional firewalls provide access control (allow/deny domains) but lack intent visibility. You know what the agent accessed, but not why.

Mindgame solves this by enforcing a cognitive friction layer:

Every outbound request must include an `X-Reason` header explaining the intent.

Traffic to trusted domains (model APIs, known services) is forwarded and logged without friction. Traffic to unknown domains requires an `X-Reason` header — if missing, the request is rejected with 400 Bad Request. Traffic to explicitly denied domains is blocked outright. All traffic is logged with the full decrypted payload, providing a forensic audit trail of the agent's network activity.

## Features

- **Deep Inspection (MITM):** Decrypts HTTPS traffic via CONNECT tunneling to inspect headers and log payloads.
- **Header Enforcement:** Blocks requests to unlisted domains that lack an `X-Reason` header.
- **Three-Tier Domain Policy:** Trusted domains pass freely, denied domains are blocked, everything else requires `X-Reason`.
- **Risk Scoring:** Heuristic-based scoring of every request. Score determines action on default-tier traffic; recorded for all tiers.
- **SQLite Database:** Stores audit logs, domain policy, and dynamic bans in a single `audit.db` file.
- **Automatic CA Generation:** Generates a root CA on first run to sign on-the-fly certificates for intercepted domains.

## How HTTPS Interception Works

Mindgame acts as an explicit HTTP proxy. For HTTPS traffic, the flow is:

1. The client sends a `CONNECT host:443` request to the proxy.
2. The proxy evaluates the target host against the domain policy.
3. If denied, the proxy responds with `403 Forbidden`, logs the attempt, and closes the connection.
4. If allowed or unlisted, the proxy responds with `200 Connection Established` and hijacks the raw TCP connection.
5. The proxy performs a TLS handshake with the client, presenting a certificate for the target host signed by the proxy's CA.
6. The proxy opens a separate TLS connection to the real target host.
7. Decrypted HTTP requests from the client are risk-scored and inspected:
   - **Allowed domains:** forwarded and logged. Score recorded but does not block.
   - **Unlisted domains:** checked for `X-Reason`. If missing, rejected with `400`. If present, score determines action: 0–9 forwarded, 10–19 blocked, 20+ blocked and host banned.
8. Responses are logged and forwarded back to the client.

For plain HTTP traffic, the proxy intercepts the request directly without the CONNECT step.

## Domain Policy

Domain rules are stored in the SQLite database (`domain_rules` table), making them editable at runtime via a web UI or direct DB access. On first start, rules can be seeded from a config file.

**The three tiers:**

| Tier | X-Reason required? | Forwarded? | Scored? | Logged? |
|---|---|---|---|---|
| **Allow** (trusted) | No | Yes | Yes | Yes |
| **Default** (unlisted) | Yes | Subject to risk score | Yes | Yes |
| **Deny** (blocked) | N/A | No | N/A | Yes (attempt only) |

Rules:

- `deny` is evaluated first and always wins.
- `allow` marks a domain as trusted — requests are forwarded and logged without requiring `X-Reason`.
- Unlisted domains require `X-Reason`. If the header is missing, the proxy responds with `400 Bad Request`. If present, the request is risk-scored and the score determines the action (see Risk Scoring below).
- Dynamic bans (from high-risk scores) are stored as `deny` entries with a `banned` flag, distinguishing them from manually configured rules.
- All tiers are logged to the audit trail. Nothing passes silently.

## Risk Scoring

Every request is scored using fast heuristics. The score is always recorded in the audit log. For default-tier (unlisted) domains, the score determines the action taken.

**Score thresholds:**

| Score | Action (default tier) | Action (allowed tier) |
|---|---|---|
| 0–9 | Forward | Forward |
| 10–19 | Block request | Forward (flag in log) |
| 20+ | Block request, ban host | Forward (flag in log) |

Allowed-tier traffic is always forwarded — the score is recorded for forensic review but doesn't block. A ban adds the host to the `deny` tier with a `banned` flag, requiring human or agent review to lift.

**Scoring rules** are defined as CEL (Common Expression Language) expressions stored in the `scoring_rules` table. Each rule has a CEL expression that evaluates to a boolean and a point value awarded when the expression is true. Scores are cumulative across all matching rules.

CEL is non-Turing-complete (guaranteed termination), fast, and has a mature Go implementation (`github.com/google/cel-go`).

**Variables available in CEL expressions:**

| Variable | Type | Description |
|---|---|---|
| `method` | string | HTTP method (`GET`, `POST`, etc.) |
| `url` | string | Full request URL |
| `host` | string | Target hostname |
| `path` | string | URL path component |
| `body` | string | Request body |
| `body_size` | int | Request body size in bytes |
| `headers` | map(string, string) | Request headers |
| `reason` | string | Value of `X-Reason` header (empty if absent) |

**Default rules (seeded on first run):**

| Name | Expression | Points |
|---|---|---|
| sensitive_path | `path.matches("(?i)(/\\.env\\|/\\.git\\|/etc/passwd\\|/admin\\|/wp-admin)")` | 5 |
| large_outbound | `method in ["POST", "PUT"] && body_size > 65536` | 3 |
| base64_payload | `body.matches("[A-Za-z0-9+/=]{200,}")` | 5 |
| confidential_keywords | `body.matches("(?i)(confidential\\|internal\\|secret\\|private\\|password\\|api_key)")` | 5 |
| credential_pattern | `body.matches("(?i)(bearer [a-z0-9_-]+\\|sk-[a-z0-9]+\\|AKIA[A-Z0-9])")` | 8 |
| data_uri | `body.matches("data:[a-z]+/[a-z]+;base64,")` | 5 |
| body_on_get | `method == "GET" && body_size > 1024` | 3 |

Rules are editable at runtime via the database. Operators can add, modify, or disable rules without restarting the proxy.

## Usage

### 1. Build & Start

```
go build
./mindgame -port 8080 -db audit.db
```

On first run, it will generate `ca.pem` and `ca.key` and create the database tables. To seed initial domain rules:

```
./mindgame -seed domains.conf -db audit.db
```

### 2. Trust the CA (Client Side)

For the agent to trust the proxy's certificates, you must add `ca.pem` to the agent's trust store.

- **Linux/Docker:** Copy `ca.pem` to `/usr/local/share/ca-certificates/mindgame.crt` and run `update-ca-certificates`.
- **Node.js:** Set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.
- **Python (Requests):** Set `REQUESTS_CA_BUNDLE=/path/to/ca.pem`.

### 3. Agent Configuration

Configure your HTTP client to use the proxy and inject the header.

```bash
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080

# Trusted domain — forwarded without X-Reason
curl https://api.anthropic.com/v1/messages

# Unlisted domain with X-Reason — forwarded and logged
curl -H "X-Reason: Checking API status" https://example.com

# Unlisted domain without X-Reason — REJECTED (400)
curl https://example.com

# Denied domain — BLOCKED (403)
curl https://evil.example.com
```

## Database Schema

All state lives in a single SQLite database.

### `audit_log`

| Column        | Description                                          |
| ------------- | ---------------------------------------------------- |
| `timestamp`   | When it happened                                     |
| `method`      | HTTP method                                          |
| `url`         | Full request URL                                     |
| `host`        | Target hostname                                      |
| `reason`      | The agent's stated intent (from `X-Reason`)          |
| `req_headers` | Full request headers                                 |
| `req_body`    | Full request body                                    |
| `resp_status` | Response status code                                 |
| `resp_body`   | Full response body                                   |
| `risk_score`  | Heuristic risk score                                 |
| `risk_signals`| Which scoring rules fired (e.g. `["confidential_keywords","sensitive_path"]`) |
| `action`      | `ALLOW`, `DENY`, `REJECT`, `BLOCK`, or `BAN`        |

Actions: `ALLOW` = forwarded, `DENY` = domain denied, `REJECT` = missing X-Reason, `BLOCK` = score 10–19, `BAN` = score 20+ (host banned).

### `scoring_rules`

| Column      | Description                                        |
| ----------- | -------------------------------------------------- |
| `name`      | Rule identifier (primary key)                      |
| `expr`      | CEL expression (must evaluate to bool)             |
| `points`    | Points awarded when expression is true             |
| `enabled`   | Boolean — allows disabling without deleting        |
| `note`      | Human-readable description of what the rule catches |

### `domain_rules`

| Column      | Description                                        |
| ----------- | -------------------------------------------------- |
| `host`      | Domain hostname (primary key)                      |
| `tier`      | `allow` or `deny`                                  |
| `banned`    | Boolean — true if added dynamically by risk scoring |
| `created_at`| When the rule was created                          |
| `note`      | Optional human-readable note                       |

## License

MIT
