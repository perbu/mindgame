package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/perbu/mindgame/internal/db"
)

func setupTest(t *testing.T) (*Handler, *db.Store) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store), store
}

func TestHandleHTTPForward(t *testing.T) {
	handler, store := setupTest(t)

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
	handler, _ := setupTest(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write([]byte("echo: " + string(body)))
	}))
	defer origin.Close()

	parsedURL, _ := url.Parse(origin.URL + "/post")
	req := httptest.NewRequest("POST", origin.URL+"/post", bytes.NewReader([]byte("payload")))
	req.URL = parsedURL
	req.RequestURI = origin.URL + "/post"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "echo: payload" {
		t.Errorf("body = %q, want %q", string(body), "echo: payload")
	}
}

func TestHopByHopHeadersStripped(t *testing.T) {
	handler, _ := setupTest(t)

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

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotProxyAuth != "" {
		t.Errorf("Proxy-Authorization was forwarded: %q", gotProxyAuth)
	}
}
