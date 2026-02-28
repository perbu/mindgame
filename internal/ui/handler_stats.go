package ui

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetAuditStats(time.Hour)
	if err != nil {
		slog.Error("get audit stats", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	templates.StatsPage(stats).Render(r.Context(), w)
}

func (s *Server) handleStatsData(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetAuditStats(time.Hour)
	if err != nil {
		slog.Error("get audit stats data", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	templates.StatsContent(stats).Render(r.Context(), w)
}
