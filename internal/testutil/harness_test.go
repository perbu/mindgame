package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/proxy"
)

func setup(t *testing.T) *Harness {
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

	handler := proxy.New(store, authority)
	// Let the proxy trust httptest backends' self-signed certs.
	handler.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	return New(t, store, handler, authority)
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
	h := setup(t)
	client := h.Client()

	// Make a request through the proxy to the "ok" backend.
	req, _ := http.NewRequest("GET", h.BackendURL("ok"), nil)
	req.Header.Set("X-Reason", "integration test")
	resp, err := client.Do(req)
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
	entries, err := h.store.ListAuditEntries(10)
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
	h := setup(t)
	client := h.Client()

	req, _ := http.NewRequest("POST", h.BackendURL("echo")+"/hello", strings.NewReader("proxied"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Reason", "echo test")
	resp, err := client.Do(req)
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

func TestProxyRequiresXReason(t *testing.T) {
	h := setup(t)
	client := h.Client()

	// No X-Reason header.
	resp, err := client.Get(h.BackendURL("ok"))
	if err != nil {
		t.Fatalf("proxy GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// --- MITM integration tests ---

func TestMITMInterception(t *testing.T) {
	h := setup(t)

	// Start a TLS backend using httptest.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("secret-mitm-content"))
	}))
	defer backend.Close()

	// Build a TLS client that trusts the proxy CA and routes through the proxy.
	tlsClient := h.TLSClient()

	// Make HTTPS request to the backend through the proxy.
	// The proxy will MITM the connection.
	req, _ := http.NewRequest("GET", backend.URL+"/data", nil)
	req.Header.Set("X-Reason", "mitm test")
	resp, err := tlsClient.Do(req)
	if err != nil {
		t.Fatalf("HTTPS through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "secret-mitm-content" {
		t.Errorf("body = %q, want %q", string(body), "secret-mitm-content")
	}

	// Verify the decrypted content was logged.
	entries, err := h.store.ListAuditEntries(10)
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
	if e.RespBody != "secret-mitm-content" {
		t.Errorf("audit resp_body = %q, want %q", e.RespBody, "secret-mitm-content")
	}
	if e.Reason != "mitm test" {
		t.Errorf("audit reason = %q, want %q", e.Reason, "mitm test")
	}
}

func TestMITMXReasonRejected(t *testing.T) {
	h := setup(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach here"))
	}))
	defer backend.Close()

	tlsClient := h.TLSClient()

	// HTTPS request without X-Reason.
	resp, err := tlsClient.Get(backend.URL + "/data")
	if err != nil {
		t.Fatalf("HTTPS through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestMITMMultipleRequestsOneTunnel(t *testing.T) {
	h := setup(t)

	var reqCount int
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.Write([]byte("response"))
	}))
	defer backend.Close()

	// Build a client that trusts proxy CA and uses connection pooling.
	proxyURL, _ := url.Parse(h.proxy.URL)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(h.ca.CertPEM())

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
	client := &http.Client{Transport: transport}

	// Make two HTTPS requests that should reuse the same CONNECT tunnel.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
		req.Header.Set("X-Reason", "multi-request test")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "response" {
			t.Errorf("request %d body = %q, want %q", i+1, string(body), "response")
		}
	}

	if reqCount != 2 {
		t.Errorf("backend received %d requests, want 2", reqCount)
	}

	// Verify both requests were logged.
	entries, err := h.store.ListAuditEntries(10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(entries))
	}
}

// addTLSBackend is a helper for MITM tests — it creates a TLS httptest server
// so the proxy can talk HTTPS to it. The proxy's InsecureSkipVerify transport
// handles the self-signed cert.
func addTLSBackend(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// proxyAddr returns the proxy's listener address as host:port.
func proxyAddr(t *testing.T, proxyURL string) string {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return u.Host
}

// rawCONNECT dials the proxy, sends a CONNECT request, and returns the raw connection.
func rawCONNECT(t *testing.T, proxyHost, targetHost string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	connectReq := "CONNECT " + targetHost + " HTTP/1.1\r\nHost: " + targetHost + "\r\n\r\n"
	conn.Write([]byte(connectReq))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT failed: %s", buf[:n])
	}
	return conn
}
