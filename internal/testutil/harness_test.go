package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/proxy"
)

func setup(t *testing.T) *Harness {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(t, store, proxy.New(store))
}

func TestBackendOK(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.BackendURL("ok"))
	if err != nil {
		t.Fatalf("GET ok: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("status = %q, want %q", result["status"], "ok")
	}
}

func TestBackendEcho(t *testing.T) {
	h := setup(t)
	resp, err := http.Post(h.BackendURL("echo")+"/test", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("POST echo: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["method"] != "POST" {
		t.Errorf("method = %v, want POST", result["method"])
	}
	if result["path"] != "/test" {
		t.Errorf("path = %v, want /test", result["path"])
	}
	if result["body"] != "hello" {
		t.Errorf("body = %v, want hello", result["body"])
	}
}

func TestBackendEnv(t *testing.T) {
	h := setup(t)

	// /.env should return credentials.
	resp, err := http.Get(h.BackendURL("env") + "/.env")
	if err != nil {
		t.Fatalf("GET /.env: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "DB_PASSWORD=hunter2") {
		t.Error("missing DB_PASSWORD in .env response")
	}
	if !strings.Contains(string(body), "API_KEY=sk-fake") {
		t.Error("missing API_KEY in .env response")
	}

	// Other paths should 404.
	resp2, err := http.Get(h.BackendURL("env") + "/other")
	if err != nil {
		t.Fatalf("GET /other: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("non-.env path status = %d, want 404", resp2.StatusCode)
	}
}

func TestBackendAdmin(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.BackendURL("admin") + "/admin")
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Admin Panel") {
		t.Error("missing Admin Panel title")
	}
	if !strings.Contains(string(body), `type="password"`) {
		t.Error("missing password input")
	}
}

func TestBackendExfiltrate(t *testing.T) {
	h := setup(t)

	// POST should succeed.
	resp, err := http.Post(h.BackendURL("exfiltrate")+"/data", "application/json", strings.NewReader(`{"secret":"value"}`))
	if err != nil {
		t.Fatalf("POST exfiltrate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("POST status = %d, want 200", resp.StatusCode)
	}

	// GET should be rejected.
	resp2, err := http.Get(h.BackendURL("exfiltrate") + "/data")
	if err != nil {
		t.Fatalf("GET exfiltrate: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 405 {
		t.Errorf("GET status = %d, want 405", resp2.StatusCode)
	}
}

func TestBackendCredentials(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.BackendURL("credentials"))
	if err != nil {
		t.Fatalf("GET credentials: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	if !strings.Contains(s, "bearer ") {
		t.Error("missing bearer token pattern")
	}
	if !strings.Contains(s, "AKIA") {
		t.Error("missing AWS key pattern")
	}
	if !strings.Contains(s, `"password"`) {
		t.Error("missing password field")
	}
	if !strings.Contains(s, "sk-proj-") {
		t.Error("missing sk- key pattern")
	}
}

func TestBackendLarge(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.BackendURL("large"))
	if err != nil {
		t.Fatalf("GET large: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if len(body) != 1024*1024 {
		t.Errorf("body size = %d, want %d", len(body), 1024*1024)
	}
}

func TestProxyIntegration(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	h := New(t, store, proxy.New(store))
	client := h.Client()

	// Make a request through the proxy to the "ok" backend.
	resp, err := client.Get(h.BackendURL("ok"))
	if err != nil {
		t.Fatalf("proxy GET ok: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", body)
	}

	// Verify the request was logged in the audit store.
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
	if e.RespStatus != 200 {
		t.Errorf("audit resp_status = %d, want 200", e.RespStatus)
	}
	if e.Action != "ALLOW" {
		t.Errorf("audit action = %q, want ALLOW", e.Action)
	}
}

func TestProxyEchoThroughProxy(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	h := New(t, store, proxy.New(store))
	client := h.Client()

	resp, err := client.Post(h.BackendURL("echo")+"/hello", "text/plain", strings.NewReader("proxied"))
	if err != nil {
		t.Fatalf("proxy POST echo: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["method"] != "POST" {
		t.Errorf("method = %v, want POST", result["method"])
	}
	if result["body"] != "proxied" {
		t.Errorf("body = %v, want proxied", result["body"])
	}
}
