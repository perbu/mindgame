package main

import (
	"crypto/tls"
	"crypto/x509"
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
	"github.com/perbu/mindgame/internal/proxy"
)

const testReloadInterval = time.Hour

func TestIntegrationHTTPProxy(t *testing.T) {
	// 1. Start an origin server.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "integration")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("origin response"))
	}))
	defer origin.Close()

	// 2. Open temp DB and create proxy with CA.
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer store.Close()

	authority, err := ca.New(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	pol, err := policy.NewCache(store, testReloadInterval)
	if err != nil {
		t.Fatalf("policy.NewCache: %v", err)
	}
	defer pol.Stop()

	handler := proxy.New(store, authority, pol)

	// 3. Start proxy on a random port.
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// 4. Configure HTTP client to use the proxy.
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// 5. Make request through the proxy to the origin.
	req, _ := http.NewRequest("GET", origin.URL+"/hello", nil)
	req.Header.Set("X-Reason", "integration test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "origin response" {
		t.Errorf("body = %q, want %q", string(body), "origin response")
	}
	if resp.Header.Get("X-Test") != "integration" {
		t.Error("missing X-Test header from origin")
	}

	// 6. Verify audit log entry.
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
	if e.RespBody != "origin response" {
		t.Errorf("audit resp_body = %q, want %q", e.RespBody, "origin response")
	}
}

func TestIntegrationCONNECT(t *testing.T) {
	// TLS backend that the proxy will MITM.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("tls-intercepted"))
	}))
	defer backend.Close()

	// Open temp DB and create proxy with CA.
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer store.Close()

	authority, err := ca.New(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	pol2, err := policy.NewCache(store, testReloadInterval)
	if err != nil {
		t.Fatalf("policy.NewCache: %v", err)
	}
	defer pol2.Stop()

	handler := proxy.New(store, authority, pol2)
	// Let the proxy trust the httptest backend's self-signed cert.
	handler.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Build a client that trusts the proxy CA.
	proxyURL, _ := url.Parse(proxyServer.URL)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	// Make HTTPS request through the proxy.
	req, _ := http.NewRequest("GET", backend.URL+"/secret", nil)
	req.Header.Set("X-Reason", "connect integration test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "tls-intercepted" {
		t.Errorf("body = %q, want %q", string(body), "tls-intercepted")
	}

	// Verify the decrypted traffic was logged.
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
	if e.RespBody != "tls-intercepted" {
		t.Errorf("audit resp_body = %q, want %q", e.RespBody, "tls-intercepted")
	}
	if e.Reason != "connect integration test" {
		t.Errorf("audit reason = %q, want %q", e.Reason, "connect integration test")
	}
}
