package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
)

const testReloadInterval = time.Hour

func setupTest(t *testing.T) (*Handler, *db.Store, *policy.Cache) {
	t.Helper()
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	authority, err := ca.New(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	pol, err := policy.NewCache(store, testReloadInterval)
	if err != nil {
		t.Fatalf("policy.NewCache: %v", err)
	}
	t.Cleanup(pol.Stop)

	return New(store, authority, pol), store, pol
}

func TestHandleHTTPForward(t *testing.T) {
	handler, store, _ := setupTest(t)

	// Origin server.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from origin"))
	}))
	defer origin.Close()

	// Build a proxy-style request (absolute URL).
	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.Header.Set("X-Reason", "unit test")
	req.RequestURI = origin.URL + "/test"

	// The proxy needs to see an absolute URL to forward properly.
	parsedURL, _ := url.Parse(origin.URL + "/test")
	req.URL = parsedURL

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "hello from origin" {
		t.Errorf("body = %q, want %q", string(body), "hello from origin")
	}
	if resp.Header.Get("X-Origin") != "true" {
		t.Error("missing X-Origin response header")
	}

	// Verify audit entry.
	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Method != "GET" {
		t.Errorf("audit method = %q, want GET", e.Method)
	}
	if e.Action != "ALLOW" {
		t.Errorf("audit action = %q, want ALLOW", e.Action)
	}
	if e.RespStatus != 200 {
		t.Errorf("audit resp_status = %d, want 200", e.RespStatus)
	}
	if e.Reason != "unit test" {
		t.Errorf("audit reason = %q, want %q", e.Reason, "unit test")
	}
}

func TestHandleHTTPForwardWithBody(t *testing.T) {
	handler, _, _ := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write([]byte("echo: " + string(body)))
	}))
	defer origin.Close()

	parsedURL, _ := url.Parse(origin.URL + "/post")
	req := httptest.NewRequest("POST", origin.URL+"/post", bytes.NewReader([]byte("payload")))
	req.URL = parsedURL
	req.RequestURI = origin.URL + "/post"
	req.Header.Set("X-Reason", "test post")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "echo: payload" {
		t.Errorf("body = %q, want %q", string(body), "echo: payload")
	}
}

func TestHopByHopHeadersStripped(t *testing.T) {
	handler, _, _ := setupTest(t)

	var gotProxyAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	parsedURL, _ := url.Parse(origin.URL + "/test")
	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.URL = parsedURL
	req.RequestURI = origin.URL + "/test"
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Reason", "test hop-by-hop")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotProxyAuth != "" {
		t.Errorf("Proxy-Authorization was forwarded: %q", gotProxyAuth)
	}
}

func TestHandleHTTPRequiresXReason(t *testing.T) {
	handler, _, _ := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	parsedURL, _ := url.Parse(origin.URL + "/test")
	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.URL = parsedURL
	req.RequestURI = origin.URL + "/test"
	// No X-Reason header set.

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !bytes.Contains(body, []byte("X-Reason")) {
		t.Errorf("body = %q, want mention of X-Reason", string(body))
	}
}

func TestHandleHTTPDenyDomain(t *testing.T) {
	handler, store, pol := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	// Parse origin host and insert deny rule.
	parsedURL, _ := url.Parse(origin.URL)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: parsedURL.Hostname(), Tier: "deny", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.URL, _ = url.Parse(origin.URL + "/test")
	req.RequestURI = origin.URL + "/test"
	req.Header.Set("X-Reason", "should be denied")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Action != "DENY" {
		t.Errorf("action = %q, want DENY", entries[0].Action)
	}
}

func TestHandleHTTPAllowDomain(t *testing.T) {
	handler, store, pol := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))
	defer origin.Close()

	parsedURL, _ := url.Parse(origin.URL)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: parsedURL.Hostname(), Tier: "allow", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}

	// Request WITHOUT X-Reason — should still succeed because domain is allowed.
	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.URL, _ = url.Parse(origin.URL + "/test")
	req.RequestURI = origin.URL + "/test"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Action != "ALLOW" {
		t.Errorf("action = %q, want ALLOW", entries[0].Action)
	}
}

func TestHandleHTTPDefaultRejectLogged(t *testing.T) {
	handler, store, _ := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	// Default tier (no domain rule), no X-Reason → REJECT.
	parsedURL, _ := url.Parse(origin.URL + "/test")
	req := httptest.NewRequest("GET", origin.URL+"/test", nil)
	req.URL = parsedURL
	req.RequestURI = origin.URL + "/test"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Action != "REJECT" {
		t.Errorf("action = %q, want REJECT", entries[0].Action)
	}
}
