package ui

import (
	"net/http"
	"time"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	// HTMX partial — return just the table body.
	if r.Header.Get("HX-Request") == "true" {
		rules, err := s.store.ListDomainRulesFiltered(search)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		templates.DomainRows(rules).Render(r.Context(), w)
		return
	}

	rules, err := s.store.ListDomainRulesFiltered(search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.DomainsPage(rules).Render(r.Context(), w)
}

func (s *Server) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	tier := r.FormValue("tier")
	note := r.FormValue("note")

	if host == "" || (tier != "allow" && tier != "deny") {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	err := s.store.InsertDomainRule(&db.DomainRule{
		Host:      host,
		Tier:      tier,
		CreatedAt: time.Now(),
		Note:      note,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderDomainRows(w, r)
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")

	if err := s.store.DeleteDomainRule(host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.policy.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderDomainRows(w, r)
}

func (s *Server) renderDomainRows(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListDomainRulesFiltered("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.DomainRows(rules).Render(r.Context(), w)
}
