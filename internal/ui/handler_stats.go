package ui

import (
	"net/http"
	"time"

	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetAuditStats(time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.StatsPage(stats).Render(r.Context(), w)
}

func (s *Server) handleStatsData(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetAuditStats(time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.StatsContent(stats).Render(r.Context(), w)
}
