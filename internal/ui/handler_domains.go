package ui

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	// HTMX partial — return just the table body.
	if r.Header.Get("HX-Request") == "true" {
		rules, err := s.store.ListDomainRulesFiltered(search)
		if err != nil {
			slog.Error("list domain rules filtered", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		templates.DomainRows(rules).Render(r.Context(), w)
		return
	}

	rules, err := s.store.ListDomainRulesFiltered(search)
	if err != nil {
		slog.Error("list domain rules filtered", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	templates.DomainsPage(rules).Render(r.Context(), w)
}

func (s *Server) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	tier := r.FormValue("tier")
	note := r.FormValue("note")

	if tier != "allow" && tier != "deny" {
		http.Error(w, "invalid tier", http.StatusBadRequest)
		return
	}
	if err := policy.ValidateHost(host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.store.InsertDomainRule(&db.DomainRule{
		Host:      host,
		Tier:      tier,
		CreatedAt: time.Now(),
		Note:      note,
	})
	if err != nil {
		slog.Error("insert domain rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		slog.Error("policy reload after domain create", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.renderDomainRows(w, r)
}

func (s *Server) handleDomainUpdate(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	tier := r.FormValue("tier")
	note := r.FormValue("note")
	banned := r.FormValue("banned") == "true"

	if tier != "allow" && tier != "deny" {
		http.Error(w, "invalid tier", http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateDomainRule(host, tier, banned, note); err != nil {
		slog.Error("update domain rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		slog.Error("policy reload after domain update", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.renderDomainRows(w, r)
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")

	if err := s.store.DeleteDomainRule(host); err != nil {
		slog.Error("delete domain rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		slog.Error("policy reload after domain delete", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.renderDomainRows(w, r)
}

func (s *Server) renderDomainRows(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListDomainRulesFiltered("")
	if err != nil {
		slog.Error("list domain rules for render", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	templates.DomainRows(rules).Render(r.Context(), w)
}
