package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
)

// Hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Handler is an HTTP forward proxy that logs all requests to the audit store.
type Handler struct {
	store     *db.Store
	ca        *ca.CA
	transport http.RoundTripper
}

// New creates a proxy handler backed by the given store and certificate authority.
func New(store *db.Store, authority *ca.CA) *Handler {
	return &Handler{
		store: store,
		ca:    authority,
		transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:  10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// SetTransport overrides the default transport. Useful for tests that need
// InsecureSkipVerify or custom dialing.
func (h *Handler) SetTransport(rt http.RoundTripper) {
	h.transport = rt
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// requireReason returns an error if the X-Reason header is missing or empty.
func requireReason(r *http.Request) error {
	if r.Header.Get("X-Reason") == "" {
		return errors.New("X-Reason header is required")
	}
	return nil
}

// forwardedResponse holds the buffered result of an upstream round-trip.
type forwardedResponse struct {
	statusCode int
	header     http.Header
	body       []byte
}

// forwardRequest sends an outbound request and logs it to the audit store.
func (h *Handler) forwardRequest(r *http.Request, reqBody []byte) (*forwardedResponse, error) {
	reqHeaders, _ := json.Marshal(r.Header)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("bad request: %w", err)
	}

	for key, vals := range r.Header {
		for _, v := range vals {
			outReq.Header.Add(key, v)
		}
	}
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	if len(reqBody) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		outReq.ContentLength = int64(len(reqBody))
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		return nil, fmt.Errorf("upstream error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	entry := &db.AuditEntry{
		Timestamp:   time.Now(),
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        r.URL.Hostname(),
		Reason:      r.Header.Get("X-Reason"),
		ReqHeaders:  string(reqHeaders),
		ReqBody:     string(reqBody),
		RespStatus:  resp.StatusCode,
		RespBody:    string(respBody),
		RiskScore:   0,
		RiskSignals: "[]",
		Action:      "ALLOW",
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		log.Printf("audit log error: %v", err)
	}

	return &forwardedResponse{
		statusCode: resp.StatusCode,
		header:     resp.Header,
		body:       respBody,
	}, nil
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if err := requireReason(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body.Close()

	fwd, err := h.forwardRequest(r, reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	for key, vals := range fwd.header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(fwd.statusCode)
	w.Write(fwd.body)
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Keep the full host:port for outbound requests.
	targetHost := r.Host

	// Extract hostname (without port) for cert minting.
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostname = r.Host
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	// Tell the client the tunnel is open.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap the raw connection in a TLS server using our CA.
	// Use a custom GetCertificate that falls back to the known hostname
	// when SNI is empty (e.g., IP-based connections).
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = hostname
			}
			return h.ca.MintCertificate(name)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("MITM TLS handshake failed for %s: %v", hostname, err)
		clientConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read HTTP requests from the decrypted connection.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isConnClosed(err) {
				log.Printf("MITM read request error for %s: %v", hostname, err)
			}
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		req.RequestURI = ""

		if err := requireReason(req); err != nil {
			writeErrorResponse(tlsConn, http.StatusBadRequest, err.Error())
			continue
		}

		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to read request body")
			continue
		}
		req.Body.Close()

		fwd, err := h.forwardRequest(req, reqBody)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, err.Error())
			continue
		}

		writeResponse(tlsConn, fwd)
	}
}

// writeErrorResponse writes a minimal HTTP error response to a raw connection.
func writeErrorResponse(conn net.Conn, code int, msg string) {
	resp := &http.Response{
		StatusCode: code,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(msg + "\n")),
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Write(conn)
}

// writeResponse writes a forwarded response as an HTTP response to a raw connection.
func writeResponse(conn net.Conn, fwd *forwardedResponse) {
	resp := &http.Response{
		StatusCode: fwd.statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     fwd.header,
		Body:       io.NopCloser(bytes.NewReader(fwd.body)),
	}
	resp.ContentLength = int64(len(fwd.body))
	resp.Write(conn)
}

// isConnClosed checks whether an error indicates the connection was closed.
func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	return false
}
