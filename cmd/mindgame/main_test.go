package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/proxy"
)

func TestIntegrationHTTPProxy(t *testing.T) {
	// 1. Start an origin server.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "integration")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("origin response"))
	}))
	defer origin.Close()

	// 2. Open temp DB and create proxy.
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer store.Close()

	handler := proxy.New(store)

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
	resp, err := client.Get(origin.URL + "/hello")
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
	// Origin: a plain TCP server that echoes data.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()

	targetAddr := listener.Addr().String()

	// Open temp DB and create proxy.
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer store.Close()

	handler := proxy.New(store)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Connect to the proxy and send a CONNECT request manually.
	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT.
	connectReq := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"
	conn.Write([]byte(connectReq))

	// Read response (should be 200).
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	response := string(buf[:n])
	if response != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("unexpected CONNECT response: %q", response)
	}

	// Now the tunnel is open. Send data through it.
	conn.Write([]byte("hello tunnel"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != "hello tunnel" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "hello tunnel")
	}

	// Close and verify audit entry.
	conn.Close()

	// Give goroutines a moment to finish.
	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Method != "CONNECT" {
		t.Errorf("audit method = %q, want CONNECT", entries[0].Method)
	}
}
