package ui

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/ui/templates"
)

const feedPageSize = 50

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}

	offset := (page - 1) * feedPageSize
	entries, err := s.store.ListAuditEntriesFiltered(db.AuditFilter{
		Limit:  feedPageSize + 1, // fetch one extra to detect next page
		Offset: offset,
	})
	if err != nil {
		slog.Error("list audit entries", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	hasMore := len(entries) > feedPageSize
	if hasMore {
		entries = entries[:feedPageSize]
	}

	templates.FeedPage(entries, page, hasMore).Render(r.Context(), w)
}

func (s *Server) handleFeedSSE(w http.ResponseWriter, r *http.Request) {
	slog.Debug("SSE feed client connected")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.broker.Subscribe()
	defer unsub()

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				slog.Debug("SSE feed broker closed")
				return
			}
			html, err := renderToString(r.Context(), templates.FeedRow(*entry))
			if err != nil {
				slog.Error("SSE render error", "error", err)
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", sseStripNewlines(html))
			flusher.Flush()
		case <-r.Context().Done():
			slog.Debug("SSE feed client disconnected")
			return
		}
	}
}

func (s *Server) handleFeedDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	entry, err := s.store.GetAuditEntry(id)
	if err != nil {
		slog.Error("get audit entry", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	templates.FeedDetail(entry).Render(r.Context(), w)
}

func (s *Server) handleFeedExport(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAuditEntriesFiltered(db.AuditFilter{
		Limit: 100000,
	})
	if err != nil {
		slog.Error("export audit entries", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="mindgame-audit-%s.md"`, time.Now().Format("2006-01-02")))

	fmt.Fprintf(w, "# Mindgame Audit Log\n\n")
	fmt.Fprintf(w, "Exported: %s | Entries: %d\n\n", time.Now().Format(time.RFC3339), len(entries))
	fmt.Fprintf(w, "---\n\n")

	for _, e := range entries {
		fmt.Fprintf(w, "## #%d %s %s %s (score: %d)\n\n",
			e.ID, e.Action, e.Method, e.Host, e.TotalScore())
		fmt.Fprintf(w, "- **Time:** %s\n", e.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(w, "- **URL:** %s\n", e.URL)
		if e.Reason != "" {
			fmt.Fprintf(w, "- **Reason:** %s\n", e.Reason)
		}
		fmt.Fprintf(w, "- **Request score:** %d\n", e.RiskScore)
		signals := db.ParseSignals(e.RiskSignals)
		if len(signals) > 0 {
			fmt.Fprintf(w, "- **Request signals:** %s\n", strings.Join(signals, ", "))
		}
		if e.RespRiskScore > 0 {
			fmt.Fprintf(w, "- **Response score:** %d\n", e.RespRiskScore)
			respSignals := db.ParseSignals(e.RespRiskSignals)
			if len(respSignals) > 0 {
				fmt.Fprintf(w, "- **Response signals:** %s\n", strings.Join(respSignals, ", "))
			}
		}
		fmt.Fprintf(w, "\n")
	}
}

// sseStripNewlines removes newlines so multi-line HTML can be sent as a single SSE data field.
func sseStripNewlines(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}
