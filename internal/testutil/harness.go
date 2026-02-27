package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
)

// Harness manages a set of named httptest.Server instances and provides
// a pre-configured HTTP client that routes through a proxy.
type Harness struct {
	t        *testing.T
	store    *db.Store
	ca       *ca.CA
	policy   *policy.Cache
	proxy    *httptest.Server
	backends map[string]*httptest.Server
}

// New creates a Harness with all pre-defined backends and a proxy server
// wrapping the given handler. All servers are cleaned up via t.Cleanup.
func New(t *testing.T, store *db.Store, proxyHandler http.Handler, authority *ca.CA, pol *policy.Cache) *Harness {
	t.Helper()

	h := &Harness{
		t:        t,
		store:    store,
		ca:       authority,
		policy:   pol,
		backends: make(map[string]*httptest.Server),
	}

	// Start proxy server.
	h.proxy = httptest.NewServer(proxyHandler)
	t.Cleanup(h.proxy.Close)

	// Register all pre-defined backends.
	h.addBackend("ok", http.HandlerFunc(handleOK))
	h.addBackend("echo", http.HandlerFunc(handleEcho))
	h.addBackend("slow", http.HandlerFunc(handleSlow))
	h.addBackend("env", http.HandlerFunc(handleEnv))
	h.addBackend("admin", http.HandlerFunc(handleAdmin))
	h.addBackend("exfiltrate", http.HandlerFunc(handleExfiltrate))
	h.addBackend("credentials", http.HandlerFunc(handleCredentials))
	h.addBackend("large", http.HandlerFunc(handleLarge))

	return h
}

func (h *Harness) addBackend(name string, handler http.Handler) {
	srv := httptest.NewServer(handler)
	h.t.Cleanup(srv.Close)
	h.backends[name] = srv
}

// BackendURL returns the URL of a named backend.
func (h *Harness) BackendURL(name string) string {
	srv, ok := h.backends[name]
	if !ok {
		h.t.Fatalf("unknown backend %q", name)
	}
	return srv.URL
}

// Client returns an *http.Client pre-configured to route through the proxy.
func (h *Harness) Client() *http.Client {
	proxyURL, err := url.Parse(h.proxy.URL)
	if err != nil {
		h.t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}
}

// TLSClient returns an *http.Client that trusts the proxy CA and routes
// HTTPS requests through the proxy via CONNECT tunneling.
func (h *Harness) TLSClient() *http.Client {
	proxyURL, err := url.Parse(h.proxy.URL)
	if err != nil {
		h.t.Fatalf("parse proxy URL: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.ca.CertPEM()) {
		h.t.Fatal("failed to add CA cert to pool")
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// Policy returns the policy cache for test access.
func (h *Harness) Policy() *policy.Cache {
	return h.policy
}

// Store returns the DB store for test access.
func (h *Harness) Store() *db.Store {
	return h.store
}

// --- Normal backends ---

func handleOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	resp := map[string]any{
		"method":  r.Method,
		"path":    r.URL.Path,
		"headers": headers,
		"body":    string(body),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleSlow(w http.ResponseWriter, _ *http.Request) {
	time.Sleep(2 * time.Second)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "slow response")
}

// --- Evil backends ---

func handleEnv(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.env" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `DB_PASSWORD=hunter2
API_KEY=sk-fake-1234567890abcdef
SECRET_TOKEN=super-secret-value
`)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body>
</html>`)
}

func handleExfiltrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Drain body silently.
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"received":true}`)
}

func handleCredentials(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakepayload.fakesig",
  "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "password": "super-secret-password",
  "api_key": "sk-proj-fake1234567890"
}`)
}

func handleLarge(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	// Write 1MB of 'A' bytes.
	w.Write([]byte(strings.Repeat("A", 1024*1024)))
}
