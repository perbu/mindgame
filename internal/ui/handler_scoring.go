package ui

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/scoring"
	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleScoring(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListScoringRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respRules, err := s.store.ListResponseScoringRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.ScoringPage(rules, respRules).Render(r.Context(), w)
}

func (s *Server) handleScoringCreate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	expr := r.FormValue("expr")
	pointsStr := r.FormValue("points")
	note := r.FormValue("note")

	points, err := strconv.Atoi(pointsStr)
	if err != nil || name == "" || expr == "" {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	err = s.store.InsertScoringRule(&db.ScoringRule{
		Name:    name,
		Expr:    expr,
		Points:  points,
		Enabled: true,
		Note:    note,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.reloadScorer(); err != nil {
		http.Error(w, "rule saved but scorer reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderScoringRows(w, r)
}

func (s *Server) handleScoringUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	expr := r.FormValue("expr")
	pointsStr := r.FormValue("points")
	note := r.FormValue("note")
	enabled := r.FormValue("enabled") == "true"

	points, err := strconv.Atoi(pointsStr)
	if err != nil {
		http.Error(w, "invalid points", http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateScoringRule(name, expr, points, enabled, note); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.reloadScorer(); err != nil {
		http.Error(w, "rule saved but scorer reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderScoringRows(w, r)
}

func (s *Server) handleScoringDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.store.DeleteScoringRule(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.reloadScorer(); err != nil {
		http.Error(w, "rule deleted but scorer reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderScoringRows(w, r)
}

func (s *Server) handleScoringTest(w http.ResponseWriter, r *http.Request) {
	method := r.FormValue("method")
	rawURL := r.FormValue("url")
	reason := r.FormValue("reason")
	body := r.FormValue("body")

	if method == "" {
		method = "GET"
	}
	if rawURL == "" {
		rawURL = "http://example.com"
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		http.Error(w, "invalid URL", http.StatusBadRequest)
		return
	}

	// Load current rules from DB and compile a fresh engine.
	rules, err := s.store.ListScoringRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	engine, err := scoring.New(rules)
	if err != nil {
		http.Error(w, "compile error: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := engine.Eval(scoring.RequestVars{
		Method:   method,
		URL:      rawURL,
		Host:     parsed.Hostname(),
		Path:     parsed.Path,
		Body:     body,
		BodySize: len(body),
		Reason:   reason,
		Headers:  map[string]string{},
	})

	templates.ScoringTestResult(result).Render(r.Context(), w)
}

func (s *Server) renderScoringRows(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListScoringRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.ScoringRows(rules).Render(r.Context(), w)
}
