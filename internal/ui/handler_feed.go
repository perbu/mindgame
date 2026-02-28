package ui

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAuditEntries(50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.FeedPage(entries).Render(r.Context(), w)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	templates.FeedDetail(entry).Render(r.Context(), w)
}

// sseStripNewlines removes newlines so multi-line HTML can be sent as a single SSE data field.
func sseStripNewlines(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}
