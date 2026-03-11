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
	store            *db.Store
	policy           *policy.Cache
	broker           *Broker
	auth             *Auth
	reloadScorer     func() error
	reloadRespScorer func() error
	mux              *http.ServeMux
}

// NewServer creates a UI server with all routes registered.
func NewServer(store *db.Store, pol *policy.Cache, reloadScorer func() error, reloadRespScorer func() error, broker *Broker) *Server {
	s := &Server{
		store:            store,
		policy:           pol,
		broker:           broker,
		reloadScorer:     reloadScorer,
		reloadRespScorer: reloadRespScorer,
		mux:              http.NewServeMux(),
	}

	s.auth = NewAuth()
	auth := s.auth

	// Public routes (no auth required).
	s.mux.HandleFunc("GET /auth", auth.HandleAuth)
	s.mux.HandleFunc("POST /auth/challenge", auth.HandleChallenge)
	s.mux.HandleFunc("POST /auth/verify", auth.HandleVerify)
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Protected routes — wrapped with auth middleware.
	protected := http.NewServeMux()

	// Feed
	protected.HandleFunc("GET /{$}", s.handleFeed)
	protected.HandleFunc("GET /feed/events", s.handleFeedSSE)
	protected.HandleFunc("GET /feed/detail/{id}", s.handleFeedDetail)
	protected.HandleFunc("GET /feed/export", s.handleFeedExport)

	// Domains
	protected.HandleFunc("GET /domains", s.handleDomains)
	protected.HandleFunc("POST /domains", s.handleDomainCreate)
	protected.HandleFunc("PUT /domains/{host}", s.handleDomainUpdate)
	protected.HandleFunc("DELETE /domains/{host}", s.handleDomainDelete)

	// Scoring (request rules)
	protected.HandleFunc("GET /scoring", s.handleScoring)
	protected.HandleFunc("POST /scoring", s.handleScoringCreate)
	protected.HandleFunc("POST /scoring/test", s.handleScoringTest)
	protected.HandleFunc("PUT /scoring/{name}", s.handleScoringUpdate)
	protected.HandleFunc("DELETE /scoring/{name}", s.handleScoringDelete)

	// Scoring (response rules)
	protected.HandleFunc("POST /scoring/response", s.handleRespScoringCreate)
	protected.HandleFunc("POST /scoring/response/test", s.handleRespScoringTest)
	protected.HandleFunc("PUT /scoring/response/{name}", s.handleRespScoringUpdate)
	protected.HandleFunc("DELETE /scoring/response/{name}", s.handleRespScoringDelete)

	// Stats
	protected.HandleFunc("GET /stats", s.handleStats)
	protected.HandleFunc("GET /stats/data", s.handleStatsData)

	// Dream mode
	protected.HandleFunc("GET /dream", s.handleDream)
	protected.HandleFunc("GET /dream/events", s.handleDreamEvents)

	s.mux.Handle("/", auth.RequireAuth(protected))

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
