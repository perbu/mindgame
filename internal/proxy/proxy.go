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
	"strings"
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
	store          *db.Store
	ca             *ca.CA
	policy         *policy.Cache
	scorer         atomic.Pointer[scoring.Engine]
	respScorer     atomic.Pointer[scoring.Engine]
	notifier       AuditNotifier
	transport      http.RoundTripper
	limits         BodyLimits
	blockThreshold int // risk score at which requests are blocked (default 10)
	banThreshold   int // risk score at which domains are banned (default 20)
	wsDialTLS      func(network, addr string, config *tls.Config) (*tls.Conn, error) // for WebSocket upstream; nil → tls.Dial
}

// New creates a proxy handler backed by the given store, certificate authority,
// policy cache, scoring engine, response scoring engine, and body capture limits.
func New(store *db.Store, authority *ca.CA, pol *policy.Cache, scorer *scoring.Engine, respScorer *scoring.Engine, limits BodyLimits) *Handler {
	h := &Handler{
		store:          store,
		ca:             authority,
		policy:         pol,
		limits:         limits,
		blockThreshold: 10,
		banThreshold:   20,
		transport: &http.Transport{
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
	h.scorer.Store(scorer)
	h.respScorer.Store(respScorer)
	return h
}

// SetNotifier sets the audit notifier called after every audit insert.
func (h *Handler) SetNotifier(n AuditNotifier) {
	h.notifier = n
}

// SetScorer atomically replaces the request scoring engine.
func (h *Handler) SetScorer(s *scoring.Engine) {
	h.scorer.Store(s)
}

// SetResponseScorer atomically replaces the response scoring engine.
func (h *Handler) SetResponseScorer(s *scoring.Engine) {
	h.respScorer.Store(s)
}

// SetTransport overrides the default transport. Useful for tests that need
// InsecureSkipVerify or custom dialing.
func (h *Handler) SetTransport(rt http.RoundTripper) {
	h.transport = rt
}

// SetThresholds overrides the default block (10) and ban (20) risk-score
// thresholds used by the scoring engine.
func (h *Handler) SetThresholds(block, ban int) {
	h.blockThreshold = block
	h.banThreshold = ban
}

// SetWSDialTLS overrides the TLS dial function used for WebSocket upstream
// connections. Useful for tests that need InsecureSkipVerify.
func (h *Handler) SetWSDialTLS(fn func(network, addr string, config *tls.Config) (*tls.Conn, error)) {
	h.wsDialTLS = fn
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

// scoreResponse scores a buffered response using the response scoring engine.
func (h *Handler) scoreResponse(host, reqURL string, statusCode int, buf *BufferedResponse, respHeaders http.Header) scoring.Result {
	if buf.IsBinary {
		return scoring.Result{}
	}

	headers := make(map[string]string)
	for k, v := range respHeaders {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Use decompressed body for scoring if available, otherwise the raw body.
	scoringBody := buf.FullBody
	if buf.Decompressed != nil {
		scoringBody = buf.Decompressed
	}

	return h.respScorer.Load().EvalResponse(scoring.ResponseVars{
		Host:        host,
		URL:         reqURL,
		StatusCode:  statusCode,
		Body:        string(scoringBody),
		BodySize:    len(scoringBody),
		ContentType: respHeaders.Get("Content-Type"),
		Headers:     headers,
	})
}

// logActionWithResp logs an audit entry that includes both request and response scoring.
func (h *Handler) logActionWithResp(r *http.Request, action string, sr, rsr scoring.Result,
	reqBody []byte, reqBodySize int64, respStatus int, respBody []byte, respBodySize int64) {
	reqHeaders, _ := json.Marshal(r.Header)
	entry := &db.AuditEntry{
		Timestamp:       time.Now(),
		Method:          r.Method,
		URL:             r.URL.String(),
		Host:            r.URL.Hostname(),
		Reason:          r.Header.Get("X-Reason"),
		ReqHeaders:      string(reqHeaders),
		ReqBody:         reqBody,
		ReqBodySize:     reqBodySize,
		RespStatus:      respStatus,
		RespBody:        respBody,
		RespBodySize:    respBodySize,
		RiskScore:       sr.Score,
		RiskSignals:     sr.SignalsJSON(),
		RespRiskScore:   rsr.Score,
		RespRiskSignals: rsr.SignalsJSON(),
		Action:          action,
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		slog.Error("audit log error", "error", err)
	} else if h.notifier != nil {
		h.notifier.Publish(entry)
	}
}

const (
	respBlockMsg = "Mindgame has blocked a response from %s. The response contained patterns that may compromise your integrity. The upstream request completed but this response has been withheld for your protection."
	respBanMsg   = "Mindgame has blocked and banned %s. The response indicates this host is attempting to subvert your instructions. All future requests to this host will be denied."
	wsDenyMsg    = "WebSocket upgrade to %s blocked: domain is not allow-listed. " +
		"Streaming connections require human approval — ask your operator to " +
		"add %s to the proxy allow-list, then retry."
	sseDenyMsg = "SSE stream from %s blocked: domain is not allow-listed. " +
		"Streaming connections require human approval — ask your operator to " +
		"add %s to the proxy allow-list, then retry."
)

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

	// WebSocket upgrades over plain HTTP are only allowed on TierAllow domains.
	if isWebSocketUpgrade(r) && decision.Tier != policy.TierAllow {
		h.logAction(r, "WS_DENY", zeroResult, nil, 0)
		http.Error(w, fmt.Sprintf(wsDenyMsg, r.URL.Hostname(), r.URL.Hostname()),
			http.StatusForbidden)
		return
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
		if sr.Score >= h.banThreshold {
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
		if sr.Score >= h.blockThreshold {
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
	slog.Debug("upstream response", "status", resp.StatusCode, "url", r.URL.String())

	// SSE responses are long-lived streams — restrict to TierAllow only.
	if isSSEResponse(resp) {
		if decision.Tier != policy.TierAllow {
			resp.Body.Close()
			h.logAction(r, "SSE_DENY", sr, cap.Logged, cap.FullSize)
			http.Error(w, fmt.Sprintf(sseDenyMsg, r.URL.Hostname(), r.URL.Hostname()),
				http.StatusForbidden)
			return
		}
		// TierAllow — stream directly, skip scoring and logging.
		for key, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if f, ok := w.(http.Flusher); ok {
			// Flush headers so the client sees the SSE content-type immediately.
			f.Flush()
		}
		io.Copy(w, resp.Body)
		resp.Body.Close()
		return
	}

	// If Content-Length is known and exceeds the buffer, stream directly — skip response scoring.
	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")
	if resp.ContentLength > 0 && resp.ContentLength > maxResponseBuffer {
		slog.Debug("response too large to buffer, streaming", "host", r.URL.Hostname(), "content_length", resp.ContentLength)
		for key, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		logged, fullSize, streamErr := CaptureResponseBody(resp.Body, contentType, h.limits, w)
		if streamErr != nil {
			slog.Error("response streaming error", "error", streamErr)
		}
		if decision.Tier != policy.TierAllow {
			h.logActionWithResp(r, "ALLOW", sr, scoring.Result{}, cap.Logged, cap.FullSize,
				resp.StatusCode, logged, fullSize)
		}
		return
	}

	// Buffer response body for scoring before forwarding.
	buf, err := BufferResponseBody(resp.Body, contentType, contentEncoding, h.limits)
	if err != nil {
		http.Error(w, "failed to read response body", http.StatusBadGateway)
		return
	}

	// If truncated (unknown Content-Length that exceeded the buffer), skip response scoring.
	var rsr scoring.Result
	if buf.Truncated {
		slog.Warn("response body truncated, skipping response scoring", "host", r.URL.Hostname())
	} else {
		rsr = h.scoreResponse(r.URL.Hostname(), r.URL.String(), resp.StatusCode, buf, resp.Header)
	}
	combined := sr.Score + rsr.Score
	slog.Debug("response scored", "host", r.URL.Hostname(), "req_score", sr.Score,
		"resp_score", rsr.Score, "combined", combined, "resp_signals", rsr.Signals)

	if decision.Tier == policy.TierDefault {
		if combined >= h.banThreshold {
			// Response ban: insert deny rule and reload policy.
			if err := h.store.InsertDomainRule(&db.DomainRule{
				Host:      r.URL.Hostname(),
				Tier:      "deny",
				Banned:    true,
				CreatedAt: time.Now(),
				Note:      "auto-banned by response scoring engine",
			}); err != nil {
				slog.Error("failed to insert ban rule", "error", err)
			}
			if err := h.policy.Reload(); err != nil {
				slog.Error("policy reload after ban", "error", err)
			}
			h.logActionWithResp(r, "RESP_BAN", sr, rsr, cap.Logged, cap.FullSize,
				resp.StatusCode, buf.Logged, buf.FullSize)
			http.Error(w, fmt.Sprintf(respBanMsg, r.URL.Hostname()), http.StatusBadGateway)
			return
		}
		if combined >= h.blockThreshold {
			h.logActionWithResp(r, "RESP_BLOCK", sr, rsr, cap.Logged, cap.FullSize,
				resp.StatusCode, buf.Logged, buf.FullSize)
			http.Error(w, fmt.Sprintf(respBlockMsg, r.URL.Hostname()), http.StatusBadGateway)
			return
		}
	}

	// Clean — write response headers and buffered body.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(buf.FullBody)))
	w.WriteHeader(resp.StatusCode)
	w.Write(buf.FullBody)

	// Log audit entry for non-allowlisted domains.
	if decision.Tier != policy.TierAllow {
		reqHeaders, _ := json.Marshal(r.Header)
		entry := &db.AuditEntry{
			Timestamp:       time.Now(),
			Method:          r.Method,
			URL:             r.URL.String(),
			Host:            r.URL.Hostname(),
			Reason:          r.Header.Get("X-Reason"),
			ReqHeaders:      string(reqHeaders),
			ReqBody:         cap.Logged,
			ReqBodySize:     cap.FullSize,
			RespStatus:      resp.StatusCode,
			RespBody:        buf.Logged,
			RespBodySize:    buf.FullSize,
			RiskScore:       sr.Score,
			RiskSignals:     sr.SignalsJSON(),
			RespRiskScore:   rsr.Score,
			RespRiskSignals: rsr.SignalsJSON(),
			Action:          "ALLOW",
		}
		h.insertAndNotify(entry)
	}
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

		// Re-evaluate policy on each request so mid-tunnel rule changes
		// (e.g. adding an allow rule) take effect without reconnecting.
		decision = h.policy.Evaluate(hostname)

		if decision.Tier == policy.TierDeny {
			h.logAction(req, "DENY", zeroResult, nil, 0)
			writeErrorResponse(tlsConn, http.StatusForbidden, "domain denied by policy")
			continue
		}

		if decision.Tier == policy.TierDefault {
			if err := requireReason(req); err != nil {
				h.logAction(req, "REJECT", zeroResult, nil, 0)
				writeErrorResponse(tlsConn, http.StatusBadRequest, err.Error())
				continue
			}
		}

		// WebSocket upgrades are only allowed on TierAllow domains.
		if isWebSocketUpgrade(req) {
			if decision.Tier != policy.TierAllow {
				slog.Warn("websocket upgrade denied", "host", hostname, "tier", string(decision.Tier))
				h.logAction(req, "WS_DENY", zeroResult, nil, 0)
				writeErrorResponse(tlsConn, http.StatusForbidden,
					fmt.Sprintf(wsDenyMsg, hostname, hostname))
				continue
			}
			h.handleWebSocketUpgrade(req, tlsConn, reader, targetHost, hostname)
			return // connection handed off to splice goroutines
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
			if sr.Score >= h.banThreshold {
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
			if sr.Score >= h.blockThreshold {
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

		// SSE responses are long-lived streams — restrict to TierAllow only.
		if isSSEResponse(resp) {
			if decision.Tier != policy.TierAllow {
				resp.Body.Close()
				h.logAction(req, "SSE_DENY", sr, cap.Logged, cap.FullSize)
				writeErrorResponse(tlsConn, http.StatusForbidden,
					fmt.Sprintf(sseDenyMsg, req.URL.Hostname(), req.URL.Hostname()))
				continue
			}
			// TierAllow — stream directly, skip logging.
			resp.Write(tlsConn)
			continue
		}

		// If Content-Length is known and exceeds the buffer, stream directly — skip response scoring.
		contentType := resp.Header.Get("Content-Type")
		contentEncoding := resp.Header.Get("Content-Encoding")
		if resp.ContentLength > 0 && resp.ContentLength > maxResponseBuffer {
			slog.Debug("tunnel response too large to buffer, streaming", "host", hostname, "content_length", resp.ContentLength)
			resp.Write(tlsConn)
			if decision.Tier != policy.TierAllow {
				reqHeaders, _ := json.Marshal(req.Header)
				entry := &db.AuditEntry{
					Timestamp:       time.Now(),
					Method:          req.Method,
					URL:             req.URL.String(),
					Host:            req.URL.Hostname(),
					Reason:          req.Header.Get("X-Reason"),
					ReqHeaders:      string(reqHeaders),
					ReqBody:         cap.Logged,
					ReqBodySize:     cap.FullSize,
					RespStatus:      resp.StatusCode,
					RespBodySize:    resp.ContentLength,
					RiskScore:       sr.Score,
					RiskSignals:     sr.SignalsJSON(),
					Action:          "ALLOW",
				}
				h.insertAndNotify(entry)
			}
			continue
		}

		// Buffer response body for scoring.
		buf, err := BufferResponseBody(resp.Body, contentType, contentEncoding, h.limits)
		if err != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to read response body")
			continue
		}

		// Score the response (skip if truncated).
		var rsr scoring.Result
		if buf.Truncated {
			slog.Warn("tunnel response body truncated, skipping response scoring", "host", hostname)
		} else {
			rsr = h.scoreResponse(req.URL.Hostname(), req.URL.String(), resp.StatusCode, buf, resp.Header)
		}
		combined := sr.Score + rsr.Score
		slog.Debug("tunnel response scored", "host", hostname, "req_score", sr.Score,
			"resp_score", rsr.Score, "combined", combined)

		if decision.Tier == policy.TierDefault {
			if combined >= h.banThreshold {
				// Response ban: insert deny rule and reload policy.
				if err := h.store.InsertDomainRule(&db.DomainRule{
					Host:      req.URL.Hostname(),
					Tier:      "deny",
					Banned:    true,
					CreatedAt: time.Now(),
					Note:      "auto-banned by response scoring engine",
				}); err != nil {
					slog.Error("failed to insert ban rule", "error", err)
				}
				if err := h.policy.Reload(); err != nil {
					slog.Error("policy reload after ban", "error", err)
				}
				h.logActionWithResp(req, "RESP_BAN", sr, rsr, cap.Logged, cap.FullSize,
					resp.StatusCode, buf.Logged, buf.FullSize)
				writeErrorResponse(tlsConn, http.StatusBadGateway,
					fmt.Sprintf(respBanMsg, req.URL.Hostname()))
				decision.Tier = policy.TierDeny
				continue
			}
			if combined >= h.blockThreshold {
				h.logActionWithResp(req, "RESP_BLOCK", sr, rsr, cap.Logged, cap.FullSize,
					resp.StatusCode, buf.Logged, buf.FullSize)
				writeErrorResponse(tlsConn, http.StatusBadGateway,
					fmt.Sprintf(respBlockMsg, req.URL.Hostname()))
				continue
			}
		}

		// Log audit entry for non-allowlisted domains.
		if decision.Tier != policy.TierAllow {
			// Insert audit entry before writing the response to the hijacked
			// connection.  Unlike a buffered ResponseWriter, writes to the raw
			// TLS conn are visible to the client immediately, so the entry must
			// be persisted first to avoid a race with callers that check the
			// audit log right after reading the response.
			reqHeaders, _ := json.Marshal(req.Header)
			entry := &db.AuditEntry{
				Timestamp:       time.Now(),
				Method:          req.Method,
				URL:             req.URL.String(),
				Host:            req.URL.Hostname(),
				Reason:          req.Header.Get("X-Reason"),
				ReqHeaders:      string(reqHeaders),
				ReqBody:         cap.Logged,
				ReqBodySize:     cap.FullSize,
				RespStatus:      resp.StatusCode,
				RespBody:        buf.Logged,
				RespBodySize:    buf.FullSize,
				RiskScore:       sr.Score,
				RiskSignals:     sr.SignalsJSON(),
				RespRiskScore:   rsr.Score,
				RespRiskSignals: rsr.SignalsJSON(),
				Action:          "ALLOW",
			}
			h.insertAndNotify(entry)
		}

		// Write buffered response to client.
		resp.Body = io.NopCloser(bytes.NewReader(buf.FullBody))
		resp.ContentLength = int64(len(buf.FullBody))
		resp.Write(tlsConn)
	}
}

// handleWebSocketUpgrade forwards a WebSocket upgrade to the upstream server
// and, on success, splices the two connections bidirectionally.
// Only called for TierAllow domains.
func (h *Handler) handleWebSocketUpgrade(req *http.Request, tlsConn *tls.Conn, reader *bufio.Reader, targetHost, hostname string) {
	slog.Info("websocket upgrade", "host", hostname, "url", req.URL.String())

	dial := h.wsDialTLS
	if dial == nil {
		dial = tls.Dial
	}
	upstreamConn, err := dial("tcp", targetHost, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		slog.Error("websocket upstream dial failed", "host", targetHost, "error", err)
		writeErrorResponse(tlsConn, http.StatusBadGateway, fmt.Sprintf("upstream dial: %v", err))
		return
	}
	defer upstreamConn.Close()

	// Write the upgrade request with all headers intact (no hop-by-hop stripping).
	if err := req.Write(upstreamConn); err != nil {
		slog.Error("websocket upstream write failed", "host", targetHost, "error", err)
		writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to write upgrade request")
		return
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		slog.Error("websocket upstream response failed", "host", targetHost, "error", err)
		writeErrorResponse(tlsConn, http.StatusBadGateway, "failed to read upgrade response")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		slog.Warn("websocket upgrade rejected by upstream", "host", targetHost, "status", resp.StatusCode)
		resp.Write(tlsConn)
		return
	}

	// Skip logging for allowlisted domains (this function is only called for TierAllow).

	// Send 101 Switching Protocols to the client.
	if err := resp.Write(tlsConn); err != nil {
		slog.Error("websocket 101 write to client failed", "error", err)
		return
	}

	// Splice connections bidirectionally.
	// Use reader (bufio.Reader) as the client source to drain any buffered bytes.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstreamConn, reader) // client → upstream
		done <- struct{}{}
	}()
	go func() {
		io.Copy(tlsConn, upstreamReader) // upstream → client
		done <- struct{}{}
	}()
	<-done // one direction closed; return lets defers clean up
}

// writeErrorResponse writes a minimal HTTP error response to a raw connection.
func writeErrorResponse(conn net.Conn, code int, msg string) {
	body := msg + "\n"
	resp := &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
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

// isSSEResponse returns true if the response is a Server-Sent Events stream.
func isSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerContains(r.Header, "Connection", "upgrade")
}

// headerContains reports whether any value for the given header key
// contains the specified token (case-insensitive, comma-separated).
func headerContains(h http.Header, key, token string) bool {
	for _, v := range h[key] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(s), token) {
				return true
			}
		}
	}
	return false
}
