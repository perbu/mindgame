# Mindgame

MITM audit proxy for AI agents. Intercepts HTTPS traffic, enforces intent
declarations via `X-Reason` headers, and scores requests for risk using CEL
expressions. SQLite-backed audit log and a web dashboard for monitoring.

## Code guidelines

- Idiomatic Go
- Logging: `log/slog`
- Errors: `return fmt.Errorf("io.open(%s): %w", filename, err)`

## Packages

- `cmd/mindgame` — entry point
- `internal/ca` — CA generation and TLS certificate handling
- `internal/db` — SQLite audit logging
- `internal/policy` — domain policy (allow/deny/default tiers)
- `internal/proxy` — HTTPS proxy handler and request interception
- `internal/scoring` — CEL-based risk scoring engine
- `internal/testutil` — shared test utilities
- `internal/ui` — web dashboard handlers and SSE broker
- `internal/ui/templates` — templ HTML templates

## Key dependencies

- `github.com/a-h/templ` — HTML templating
- `github.com/google/cel-go` — CEL expression evaluation
- `modernc.org/sqlite` — SQLite driver

## Version management

Run `go tool bump (-patch|-minor|-major)` after the last commit to create a
tagged release. Bump updates `cmd/mindgame/.version` (embedded in the binary)
and creates a git tag.
