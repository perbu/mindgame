package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	limits    BodyLimits
}

// New creates a proxy handler backed by the given store, certificate authority,
// policy cache, scoring engine, and body capture limits.
func New(store *db.Store, authority *ca.CA, pol *policy.Cache, scorer *scoring.Engine, limits BodyLimits) *Handler {
	h := &Handler{
		store:  store,
		ca:     authority,
		policy: pol,
		limits: limits,
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
	slog.Debug("incoming request", "method", r.Method, "url", r.URL.String())
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

// doUpstream builds an outbound request and executes the round-trip.
// The returned *http.Response has an unconsumed body that the caller must close.
func (h *Handler) doUpstream(r *http.Request, body io.Reader, contentLength int64) (*http.Response, error) {
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), body)
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

	if contentLength >= 0 {
		outReq.ContentLength = contentLength
	}

	slog.Debug("forwarding upstream", "method", r.Method, "url", r.URL.String())
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		return nil, fmt.Errorf("upstream error: %w", err)
	}
	return resp, nil
}

// logAction logs an audit entry for requests that are denied, rejected, blocked,
// or banned (no upstream request made).
func (h *Handler) logAction(r *http.Request, action string, sr scoring.Result, reqBody []byte, reqBodySize int64) {
	reqHeaders, _ := json.Marshal(r.Header)
	entry := &db.AuditEntry{
		Timestamp:   time.Now(),
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        r.URL.Hostname(),
		Reason:      r.Header.Get("X-Reason"),
		ReqHeaders:  string(reqHeaders),
		ReqBody:     reqBody,
		ReqBodySize: reqBodySize,
		RiskScore:   sr.Score,
		RiskSignals: sr.SignalsJSON(),
		Action:      action,
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		slog.Error("audit log error", "error", err)
	} else if h.notifier != nil {
		h.notifier.Publish(entry)
	}
}

// insertAndNotify inserts an audit entry and notifies subscribers.
func (h *Handler) insertAndNotify(entry *db.AuditEntry) {
	if err := h.store.InsertAuditEntry(entry); err != nil {
		slog.Error("audit log error", "error", err)
	} else if h.notifier != nil {
		h.notifier.Publish(entry)
	}
}

// scoreRequest builds RequestVars from the HTTP request and captured body.
func (h *Handler) scoreRequest(r *http.Request, cap *CapturedBody) scoring.Result {
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	var bodyStr string
	if !cap.IsBinary {
		bodyStr = string(cap.Logged)
	}
	bodySize := int(cap.FullSize)
	if bodySize < 0 {
		bodySize = len(cap.Logged)
	}

	return h.scorer.Load().Eval(scoring.RequestVars{
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.URL.Hostname(),
		Path:         r.URL.Path,
		Body:         bodyStr,
		BodySize:     bodySize,
		BodyIsBinary: cap.IsBinary,
		Reason:       r.Header.Get("X-Reason"),
		Headers:      headers,
	})
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	decision := h.policy.Evaluate(r.URL.Hostname())
	slog.Debug("policy evaluated", "host", r.URL.Hostname(), "tier", string(decision.Tier))
	var zeroResult scoring.Result

	switch decision.Tier {
	case policy.TierDeny:
		h.logAction(r, "DENY", zeroResult, nil, 0)
		http.Error(w, "domain denied by policy", http.StatusForbidden)
		return
	case policy.TierAllow:
		// Skip X-Reason check.
	default:
		if err := requireReason(r); err != nil {
			h.logAction(r, "REJECT", zeroResult, nil, 0)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Capture request body with limits.
	cap, err := CaptureRequestBody(r.Body, r.Header.Get("Content-Type"), r.ContentLength, h.limits)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body.Close()

	sr := h.scoreRequest(r, cap)
	slog.Debug("request scored", "host", r.URL.Hostname(), "score", sr.Score, "signals", sr.Signals)

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
				slog.Error("failed to insert ban rule", "error", err)
			}
			if err := h.policy.Reload(); err != nil {
				slog.Error("policy reload after ban", "error", err)
			}
			h.logAction(r, "BAN", sr, cap.Logged, cap.FullSize)
			http.Error(w, "request banned by scoring engine", http.StatusForbidden)
			return
		}
		if sr.Score >= 10 {
			h.logAction(r, "BLOCK", sr, cap.Logged, cap.FullSize)
			http.Error(w, "request blocked by scoring engine", http.StatusForbidden)
			return
		}
	}

	// Forward request upstream.
	resp, err := h.doUpstream(r, cap.FullReader, r.ContentLength)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	slog.Debug("upstream response", "status", resp.StatusCode, "url", r.URL.String())

	// Write response headers.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body to client while capturing log portion.
	respLogged, respFullSize, err := CaptureResponseBody(resp.Body, resp.Header.Get("Content-Type"), h.limits, w)
	if err != nil {
		slog.Error("response streaming error", "error", err)
	}

	// Create audit entry.
	reqHeaders, _ := json.Marshal(r.Header)
	entry := &db.AuditEntry{
		Timestamp:    time.Now(),
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.URL.Hostname(),
		Reason:       r.Header.Get("X-Reason"),
		ReqHeaders:   string(reqHeaders),
		ReqBody:      cap.Logged,
		ReqBodySize:  cap.FullSize,
		RespStatus:   resp.StatusCode,
		RespBody:     respLogged,
		RespBodySize: respFullSize,
		RiskScore:    sr.Score,
		RiskSignals:  sr.SignalsJSON(),
		Action:       "ALLOW",
	}
	h.insertAndNotify(entry)
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	slog.Debug("CONNECT tunnel", "host", r.Host)
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
	slog.Debug("tunnel policy evaluated", "host", hostname, "tier", string(decision.Tier))
	if decision.Tier == policy.TierDeny {
		// Build a synthetic request for logging.
		synth := &http.Request{
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header,
		}
		synth.URL.Host = hostname
		h.logAction(synth, "DENY", zeroResult, nil, 0)
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
		slog.Error("MITM TLS handshake failed", "host", hostname, "error", err)
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
				slog.Warn("MITM read request error", "host", hostname, "error", err)
			}
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		req.RequestURI = ""

		// If host was banned mid-tunnel, deny subsequent requests.
		if decision.Tier == policy.TierDeny {
			h.logAction(req, "DENY", zeroResult, nil, 0)
			writeErrorResponse(tlsConn, http.StatusForbidden, "domain denied by policy")
			continue
		}

		// Apply tier-based X-Reason enforcement (decision evaluated once at CONNECT time).
		if decision.Tier == policy.TierDefault {
			if err := requireReason(req); err != nil {
				h.logAction(req, "REJECT", zeroResult, nil, 0)
				writeErrorResponse(tlsConn, http.StatusBadRequest, err.Error())
				continue
			}
		}

		// Capture request body with limits.
		cap, err := CaptureRequestBody(req.Body, req.Header.Get("Content-Type"), req.ContentLength, h.limits)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to read request body")
			continue
		}
		req.Body.Close()

		sr := h.scoreRequest(req, cap)
		slog.Debug("tunnel request scored", "host", hostname, "method", req.Method, "url", req.URL.String(), "score", sr.Score)

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
					slog.Error("failed to insert ban rule", "error", err)
				}
				if err := h.policy.Reload(); err != nil {
					slog.Error("policy reload after ban", "error", err)
				}
				h.logAction(req, "BAN", sr, cap.Logged, cap.FullSize)
				writeErrorResponse(tlsConn, http.StatusForbidden, "request banned by scoring engine")
				decision.Tier = policy.TierDeny
				continue
			}
			if sr.Score >= 10 {
				h.logAction(req, "BLOCK", sr, cap.Logged, cap.FullSize)
				writeErrorResponse(tlsConn, http.StatusForbidden, "request blocked by scoring engine")
				continue
			}
		}

		// Forward request upstream.
		resp, err := h.doUpstream(req, cap.FullReader, req.ContentLength)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, err.Error())
			continue
		}

		// Stream response to client while capturing log portion.
		limit := ResponseCaptureLimit(resp.Header.Get("Content-Type"), h.limits)
		cr := newResponseCapture(resp.Body, limit)
		resp.Body = cr
		resp.Write(tlsConn)
		cr.Close()

		respLogged := cr.Logged()
		respFullSize := cr.FullSize()

		// Create audit entry.
		reqHeaders, _ := json.Marshal(req.Header)
		entry := &db.AuditEntry{
			Timestamp:    time.Now(),
			Method:       req.Method,
			URL:          req.URL.String(),
			Host:         req.URL.Hostname(),
			Reason:       req.Header.Get("X-Reason"),
			ReqHeaders:   string(reqHeaders),
			ReqBody:      cap.Logged,
			ReqBodySize:  cap.FullSize,
			RespStatus:   resp.StatusCode,
			RespBody:     respLogged,
			RespBodySize: respFullSize,
			RiskScore:    sr.Score,
			RiskSignals:  sr.SignalsJSON(),
			Action:       "ALLOW",
		}
		h.insertAndNotify(entry)
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
