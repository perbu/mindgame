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
	"sync/atomic"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
	"github.com/perbu/mindgame/internal/scoring"
)

// AuditNotifier is called after every audit entry insertion.
type AuditNotifier interface {
	Publish(entry *db.AuditEntry)
}

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
	policy    *policy.Cache
	scorer    atomic.Pointer[scoring.Engine]
	notifier  AuditNotifier
	transport http.RoundTripper
}

// New creates a proxy handler backed by the given store, certificate authority,
// policy cache, and scoring engine.
func New(store *db.Store, authority *ca.CA, pol *policy.Cache, scorer *scoring.Engine) *Handler {
	h := &Handler{
		store:  store,
		ca:     authority,
		policy: pol,
		transport: &http.Transport{
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
	h.scorer.Store(scorer)
	return h
}

// SetNotifier sets the audit notifier called after every audit insert.
func (h *Handler) SetNotifier(n AuditNotifier) {
	h.notifier = n
}

// SetScorer atomically replaces the scoring engine.
func (h *Handler) SetScorer(s *scoring.Engine) {
	h.scorer.Store(s)
}

// SetTransport overrides the default transport. Useful for tests that need
// InsecureSkipVerify or custom dialing.
func (h *Handler) SetTransport(rt http.RoundTripper) {
	h.transport = rt
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Direct (non-proxied) requests have a relative URL. Serve the CA
	// certificate so agents can bootstrap trust without out-of-band setup.
	if !r.URL.IsAbs() && r.URL.Path == "/ca.pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=mindgame-ca.pem")
		w.Write(h.ca.CertPEM())
		return
	}

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
func (h *Handler) forwardRequest(r *http.Request, reqBody []byte, sr scoring.Result, action string) (*forwardedResponse, error) {
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
		RiskScore:   sr.Score,
		RiskSignals: sr.SignalsJSON(),
		Action:      action,
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		log.Printf("audit log error: %v", err)
	} else if h.notifier != nil {
		h.notifier.Publish(entry)
	}

	return &forwardedResponse{
		statusCode: resp.StatusCode,
		header:     resp.Header,
		body:       respBody,
	}, nil
}

// logAction logs an audit entry for requests that are denied, rejected, blocked,
// or banned (no upstream request made). Optional reqBody for BLOCK/BAN forensics.
func (h *Handler) logAction(r *http.Request, action string, sr scoring.Result, reqBody ...[]byte) {
	reqHeaders, _ := json.Marshal(r.Header)
	var body string
	if len(reqBody) > 0 {
		body = string(reqBody[0])
	}
	entry := &db.AuditEntry{
		Timestamp:   time.Now(),
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        r.URL.Hostname(),
		Reason:      r.Header.Get("X-Reason"),
		ReqHeaders:  string(reqHeaders),
		ReqBody:     body,
		RespStatus:  0,
		RespBody:    "",
		RiskScore:   sr.Score,
		RiskSignals: sr.SignalsJSON(),
		Action:      action,
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		log.Printf("audit log error: %v", err)
	} else if h.notifier != nil {
		h.notifier.Publish(entry)
	}
}

// scoreRequest builds RequestVars from the HTTP request and evaluates them.
func (h *Handler) scoreRequest(r *http.Request, reqBody []byte) scoring.Result {
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return h.scorer.Load().Eval(scoring.RequestVars{
		Method:   r.Method,
		URL:      r.URL.String(),
		Host:     r.URL.Hostname(),
		Path:     r.URL.Path,
		Body:     string(reqBody),
		BodySize: len(reqBody),
		Reason:   r.Header.Get("X-Reason"),
		Headers:  headers,
	})
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	decision := h.policy.Evaluate(r.URL.Hostname())
	var zeroResult scoring.Result

	switch decision.Tier {
	case policy.TierDeny:
		h.logAction(r, "DENY", zeroResult)
		http.Error(w, "domain denied by policy", http.StatusForbidden)
		return
	case policy.TierAllow:
		// Skip X-Reason check.
	default:
		if err := requireReason(r); err != nil {
			h.logAction(r, "REJECT", zeroResult)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body.Close()

	sr := h.scoreRequest(r, reqBody)

	if decision.Tier == policy.TierDefault {
		if sr.Score >= 20 {
			// Ban: insert deny rule and reload policy.
			if err := h.store.InsertDomainRule(&db.DomainRule{
				Host:      r.URL.Hostname(),
				Tier:      "deny",
				Banned:    true,
				CreatedAt: time.Now(),
				Note:      "auto-banned by scoring engine",
			}); err != nil {
				log.Printf("failed to insert ban rule: %v", err)
			}
			if err := h.policy.Reload(); err != nil {
				log.Printf("policy reload after ban: %v", err)
			}
			h.logAction(r, "BAN", sr, reqBody)
			http.Error(w, "request banned by scoring engine", http.StatusForbidden)
			return
		}
		if sr.Score >= 10 {
			h.logAction(r, "BLOCK", sr, reqBody)
			http.Error(w, "request blocked by scoring engine", http.StatusForbidden)
			return
		}
	}

	fwd, err := h.forwardRequest(r, reqBody, sr, "ALLOW")
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

	var zeroResult scoring.Result

	// Check deny before hijacking — we can still use http.Error.
	decision := h.policy.Evaluate(hostname)
	if decision.Tier == policy.TierDeny {
		// Build a synthetic request for logging.
		synth := &http.Request{
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header,
		}
		synth.URL.Host = hostname
		h.logAction(synth, "DENY", zeroResult)
		http.Error(w, "domain denied by policy", http.StatusForbidden)
		return
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

		// If host was banned mid-tunnel, deny subsequent requests.
		if decision.Tier == policy.TierDeny {
			h.logAction(req, "DENY", zeroResult)
			writeErrorResponse(tlsConn, http.StatusForbidden, "domain denied by policy")
			continue
		}

		// Apply tier-based X-Reason enforcement (decision evaluated once at CONNECT time).
		if decision.Tier == policy.TierDefault {
			if err := requireReason(req); err != nil {
				h.logAction(req, "REJECT", zeroResult)
				writeErrorResponse(tlsConn, http.StatusBadRequest, err.Error())
				continue
			}
		}

		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to read request body")
			continue
		}
		req.Body.Close()

		sr := h.scoreRequest(req, reqBody)

		if decision.Tier == policy.TierDefault {
			if sr.Score >= 20 {
				// Ban: insert deny rule and reload policy.
				if err := h.store.InsertDomainRule(&db.DomainRule{
					Host:      req.URL.Hostname(),
					Tier:      "deny",
					Banned:    true,
					CreatedAt: time.Now(),
					Note:      "auto-banned by scoring engine",
				}); err != nil {
					log.Printf("failed to insert ban rule: %v", err)
				}
				if err := h.policy.Reload(); err != nil {
					log.Printf("policy reload after ban: %v", err)
				}
				h.logAction(req, "BAN", sr, reqBody)
				writeErrorResponse(tlsConn, http.StatusForbidden, "request banned by scoring engine")
				decision.Tier = policy.TierDeny
				continue
			}
			if sr.Score >= 10 {
				h.logAction(req, "BLOCK", sr, reqBody)
				writeErrorResponse(tlsConn, http.StatusForbidden, "request blocked by scoring engine")
				continue
			}
		}

		fwd, err := h.forwardRequest(req, reqBody, sr, "ALLOW")
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
