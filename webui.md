# Mindgame Web UI

The web UI for Mindgame provides operational dashboards for managing the proxy and a ambient visualization mode for NOC displays.

Built with [templ](https://templ.guide/) for Go HTML templating and [HTMX](https://htmx.org/) for interactivity. No JavaScript framework. Server-rendered HTML with targeted DOM updates.

## Stack

- **templ** - type-safe Go templates, compiled to Go code
- **HTMX** - HTML attributes for AJAX, WebSockets, SSE
- **SQLite** - same `audit.db` the proxy writes to
- **Embedded** - the UI is compiled into the Mindgame binary, no separate process

The web UI runs on a separate port from the proxy (e.g., `-ui-port 9090`).

## Dashboard

The operational interface. Designed for operators managing the proxy day-to-day.

### Live Feed

Default landing page. A real-time stream of requests flowing through the proxy, pushed via SSE.

Each row shows: timestamp, method, host, path, reason (truncated), risk score, action. Color-coded by action - green for ALLOW, yellow for BLOCK, red for BAN/DENY, grey for REJECT.

Clicking a row expands it inline (HTMX swap) to show full headers, body, and which scoring rules fired.

Filters (applied via HTMX, no page reload):

- Action type (ALLOW / DENY / REJECT / BLOCK / BAN)
- Host (text search)
- Minimum risk score
- Time range

### Domain Rules

CRUD interface for the `domain_rules` table.

- List all rules with tier, banned status, creation date, and note
- Add new allow/deny rules
- Lift bans (delete or convert banned entries)
- Edit notes
- Search/filter by host

Banned domains are visually distinct (flagged, sorted to top by default) so operators can review them quickly.

### Scoring Rules

CRUD interface for the `scoring_rules` table.

- List all rules with name, CEL expression, points, and enabled status
- Toggle rules on/off
- Edit expressions and point values
- Add new rules
- **Test mode:** paste a sample request (method, URL, headers, body) and see which rules fire and the total score. Useful for validating CEL expressions before enabling them.

### Statistics

Summary view with key metrics, refreshed via polling (HTMX `hx-trigger="every 30s"`).

- Requests per minute (total, by action type)
- Top hosts by request count
- Top hosts by average risk score
- Recent bans
- Scoring rule hit frequency (which rules fire most often)

## Dream Mode

A full-screen ambient visualization designed to run on a wall-mounted display in a NOC. Not for operating the proxy - for giving a room a sense of what the agents are doing.

Accessed via `/dream`. No navigation chrome, no controls. Click or press Escape to exit.

**Visual concept:**

- Dark background. Requests appear as particles or pulses flowing across the screen.
- Each request's visual properties encode its attributes:
  - **Size** - body size
  - **Color** - risk score gradient (cool blues/greens for low, warm oranges/reds for high)
  - **Speed** - allowed requests flow smoothly, blocked requests shatter or deflect
  - **Trails** - frequent hosts develop visible lanes/pathways
- Host names and reasons drift across the screen as translucent text, appearing and fading. Not readable at a glance - impressionistic.
- Bans trigger a brief, noticeable flare.
- Ambient audio cues are out of scope (for now).

**Implementation:**

- HTML5 Canvas or WebGL for rendering
- SSE feed from the same endpoint as the live feed
- Minimal JS - this is the one place where client-side rendering is justified
- Self-contained: single HTML page with inline JS, served by the Go backend

Dream mode is deliberately vague and aesthetic. It should give someone walking past a sense of "busy" vs "quiet" vs "something is wrong" without needing to read anything.
