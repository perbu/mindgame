package proxy

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"time"

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
	transport http.RoundTripper
}

// New creates a proxy handler backed by the given store.
func New(store *db.Store) *Handler {
	return &Handler{
		store: store,
		transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:  10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Buffer request body.
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body.Close()

	// Marshal request headers for logging.
	reqHeaders, _ := json.Marshal(r.Header)

	// Build outbound request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Copy headers, then strip hop-by-hop.
	for key, vals := range r.Header {
		for _, v := range vals {
			outReq.Header.Add(key, v)
		}
	}
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	// Attach body if present.
	if len(reqBody) > 0 {
		outReq.Body = io.NopCloser(io.NewSectionReader(newBytesReaderAt(reqBody), 0, int64(len(reqBody))))
		outReq.ContentLength = int64(len(reqBody))
	}

	// Execute request.
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Buffer response body.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read response body", http.StatusBadGateway)
		return
	}

	// Log to audit store.
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

	// Write response back to client.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Dial the target.
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	// Send 200 Connection Established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Log the CONNECT.
	entry := &db.AuditEntry{
		Timestamp:   time.Now(),
		Method:      "CONNECT",
		URL:         "https://" + r.Host,
		Host:        r.Host,
		Reason:      r.Header.Get("X-Reason"),
		ReqHeaders:  "{}",
		ReqBody:     "",
		RespStatus:  200,
		RespBody:    "",
		RiskScore:   0,
		RiskSignals: "[]",
		Action:      "ALLOW",
	}
	if err := h.store.InsertAuditEntry(entry); err != nil {
		log.Printf("audit log error: %v", err)
	}

	// Bidirectional copy.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish, then clean up.
	<-done
	clientConn.Close()
	targetConn.Close()
	<-done
}

// bytesReaderAt wraps a byte slice to implement io.ReaderAt.
type bytesReaderAt struct {
	data []byte
}

func newBytesReaderAt(data []byte) *bytesReaderAt {
	return &bytesReaderAt{data: data}
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
