package ui

import (
	"bytes"
	"context"
	"io/fs"
	"net/http"

	"github.com/a-h/templ"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
)

// Server serves the web UI dashboard.
type Server struct {
	store        *db.Store
	policy       *policy.Cache
	broker       *Broker
	reloadScorer func() error
	mux          *http.ServeMux
}

// NewServer creates a UI server with all routes registered.
func NewServer(store *db.Store, pol *policy.Cache, reloadScorer func() error, broker *Broker) *Server {
	s := &Server{
		store:        store,
		policy:       pol,
		broker:       broker,
		reloadScorer: reloadScorer,
		mux:          http.NewServeMux(),
	}

	// Feed
	s.mux.HandleFunc("GET /{$}", s.handleFeed)
	s.mux.HandleFunc("GET /feed/events", s.handleFeedSSE)
	s.mux.HandleFunc("GET /feed/detail/{id}", s.handleFeedDetail)

	// Domains
	s.mux.HandleFunc("GET /domains", s.handleDomains)
	s.mux.HandleFunc("POST /domains", s.handleDomainCreate)
	s.mux.HandleFunc("PUT /domains/{host}", s.handleDomainUpdate)
	s.mux.HandleFunc("DELETE /domains/{host}", s.handleDomainDelete)

	// Scoring
	s.mux.HandleFunc("GET /scoring", s.handleScoring)
	s.mux.HandleFunc("POST /scoring", s.handleScoringCreate)
	s.mux.HandleFunc("POST /scoring/test", s.handleScoringTest)
	s.mux.HandleFunc("PUT /scoring/{name}", s.handleScoringUpdate)
	s.mux.HandleFunc("DELETE /scoring/{name}", s.handleScoringDelete)

	// Stats
	s.mux.HandleFunc("GET /stats", s.handleStats)
	s.mux.HandleFunc("GET /stats/data", s.handleStatsData)

	// Static assets
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// renderToString renders a templ component to a string.
func renderToString(ctx context.Context, c templ.Component) (string, error) {
	var buf bytes.Buffer
	if err := c.Render(ctx, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}
