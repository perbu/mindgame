package ui

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/scoring"
	"github.com/perbu/mindgame/internal/ui/templates"
)

func (s *Server) handleRespScoringCreate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	expr := r.FormValue("expr")
	pointsStr := r.FormValue("points")
	note := r.FormValue("note")

	points, err := strconv.Atoi(pointsStr)
	if err != nil || name == "" || expr == "" {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	if err := scoring.ValidateResponseExpr(expr); err != nil {
		http.Error(w, "invalid expression: "+err.Error(), http.StatusBadRequest)
		return
	}

	err = s.store.InsertResponseScoringRule(&db.ScoringRule{
		Name:    name,
		Expr:    expr,
		Points:  points,
		Enabled: true,
		Note:    note,
	})
	if err != nil {
		slog.Error("insert response scoring rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.reloadRespScorer(); err != nil {
		slog.Error("reload resp scorer after create", "error", err)
		http.Error(w, "rule saved but failed to activate", http.StatusInternalServerError)
		return
	}

	s.renderRespScoringRows(w, r)
}

func (s *Server) handleRespScoringUpdate(w http.ResponseWriter, r *http.Request) {
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

	if err := scoring.ValidateResponseExpr(expr); err != nil {
		http.Error(w, "invalid expression: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateResponseScoringRule(name, expr, points, enabled, note); err != nil {
		slog.Error("update response scoring rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.reloadRespScorer(); err != nil {
		slog.Error("reload resp scorer after update", "error", err)
		http.Error(w, "rule saved but failed to activate", http.StatusInternalServerError)
		return
	}

	s.renderRespScoringRows(w, r)
}

func (s *Server) handleRespScoringDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.store.DeleteResponseScoringRule(name); err != nil {
		slog.Error("delete response scoring rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.reloadRespScorer(); err != nil {
		slog.Error("reload resp scorer after delete", "error", err)
		http.Error(w, "rule deleted but failed to activate", http.StatusInternalServerError)
		return
	}

	s.renderRespScoringRows(w, r)
}

func (s *Server) handleRespScoringTest(w http.ResponseWriter, r *http.Request) {
	statusStr := r.FormValue("status_code")
	body := r.FormValue("body")
	contentType := r.FormValue("content_type")
	host := r.FormValue("host")

	statusCode, err := strconv.Atoi(statusStr)
	if err != nil {
		statusCode = 200
	}
	if host == "" {
		host = "example.com"
	}
	if contentType == "" {
		contentType = "text/html"
	}

	// Load current response rules from DB and compile a fresh engine.
	rules, err := s.store.ListResponseScoringRules()
	if err != nil {
		slog.Error("list response scoring rules for test", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	engine, err := scoring.NewResponse(rules)
	if err != nil {
		http.Error(w, "compile error: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := engine.EvalResponse(scoring.ResponseVars{
		Host:        host,
		URL:         "https://" + host + "/",
		StatusCode:  statusCode,
		Body:        body,
		BodySize:    len(body),
		ContentType: contentType,
		Headers:     map[string]string{},
	})

	templates.ScoringTestResult(result).Render(r.Context(), w)
}

func (s *Server) renderRespScoringRows(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListResponseScoringRules()
	if err != nil {
		slog.Error("list response scoring rules for render", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	templates.RespScoringRows(rules).Render(r.Context(), w)
}
