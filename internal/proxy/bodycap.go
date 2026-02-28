package proxy

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

// BodyLimits controls how much body data is captured for audit logging.
type BodyLimits struct {
	MaxTextLog   int // max bytes logged for text bodies (default 1MB)
	MaxBinaryLog int // max bytes logged for binary bodies (default 64KB)
}

// DefaultBodyLimits returns the default body capture limits.
func DefaultBodyLimits() BodyLimits {
	return BodyLimits{
		MaxTextLog:   1 << 20, // 1 MB
		MaxBinaryLog: 1 << 16, // 64 KB
	}
}

// CapturedBody holds the result of capturing a request body.
type CapturedBody struct {
	Logged     []byte    // the portion saved for audit
	FullSize   int64     // total body size (-1 if unknown/streaming)
	IsBinary   bool      // whether the body appears to be binary
	Truncated  bool      // whether the logged portion was truncated
	FullReader io.Reader // reconstituted reader for forwarding the complete body
}

// CaptureRequestBody reads up to the configured limit from body, detects
// whether the content is binary, and returns a CapturedBody. The FullReader
// field provides the complete body for forwarding upstream.
func CaptureRequestBody(body io.Reader, contentType string, contentLength int64, limits BodyLimits) (*CapturedBody, error) {
	if body == nil {
		return &CapturedBody{FullSize: 0}, nil
	}

	maxProbe := limits.MaxTextLog
	if limits.MaxBinaryLog > maxProbe {
		maxProbe = limits.MaxBinaryLog
	}

	probe := make([]byte, maxProbe+1)
	n, readErr := io.ReadFull(body, probe)
	probe = probe[:n]

	isBinary := isBinaryContent(contentType, probe)

	logLimit := limits.MaxTextLog
	if isBinary {
		logLimit = limits.MaxBinaryLog
	}

	logged := probe
	truncated := false
	if len(logged) > logLimit {
		logged = logged[:logLimit]
		truncated = true
	}

	fullSize := contentLength

	var fullReader io.Reader
	if readErr == nil {
		// Body exceeds probe — more data available.
		fullReader = io.MultiReader(bytes.NewReader(probe), body)
		truncated = true
	} else {
		// All data fit within probe (EOF or ErrUnexpectedEOF).
		fullReader = bytes.NewReader(probe)
		if fullSize < 0 {
			fullSize = int64(n)
		}
	}

	return &CapturedBody{
		Logged:     logged,
		FullSize:   fullSize,
		IsBinary:   isBinary,
		Truncated:  truncated,
		FullReader: fullReader,
	}, nil
}

// responseCapture wraps an io.ReadCloser, capturing the first limit bytes
// while passing all reads through to the caller.
type responseCapture struct {
	r     io.ReadCloser
	buf   bytes.Buffer
	limit int
	total int64
}

func newResponseCapture(r io.ReadCloser, limit int) *responseCapture {
	return &responseCapture{r: r, limit: limit}
}

func (c *responseCapture) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += int64(n)
	if remaining := c.limit - c.buf.Len(); remaining > 0 && n > 0 {
		toCapture := n
		if toCapture > remaining {
			toCapture = remaining
		}
		c.buf.Write(p[:toCapture])
	}
	return n, err
}

func (c *responseCapture) Close() error {
	return c.r.Close()
}

// Logged returns the captured portion of the body.
func (c *responseCapture) Logged() []byte { return c.buf.Bytes() }

// FullSize returns the total number of bytes read from the body.
func (c *responseCapture) FullSize() int64 { return c.total }

// CaptureResponseBody streams the response body to dst while capturing up to
// the configured limit for audit logging. Returns captured bytes and total size.
func CaptureResponseBody(body io.ReadCloser, contentType string, limits BodyLimits, dst io.Writer) (logged []byte, fullSize int64, err error) {
	limit := limits.MaxTextLog
	if isBinaryContentType(contentType) {
		limit = limits.MaxBinaryLog
	}
	cr := newResponseCapture(body, limit)
	fullSize, err = io.Copy(dst, cr)
	return cr.Logged(), fullSize, err
}

// ResponseCaptureLimit returns the appropriate capture limit for a given
// content type, for use with newResponseCapture directly.
func ResponseCaptureLimit(contentType string, limits BodyLimits) int {
	if isBinaryContentType(contentType) {
		return limits.MaxBinaryLog
	}
	return limits.MaxTextLog
}

// maxResponseBuffer is the hard cap for buffering response bodies (10MB).
const maxResponseBuffer = 10 << 20

// BufferedResponse holds a fully buffered response body for scoring and forwarding.
type BufferedResponse struct {
	Logged   []byte // portion saved for audit logging
	FullBody []byte // complete body for forwarding
	FullSize int64  // total body size
	IsBinary bool   // whether the body is binary content
}

// BufferResponseBody reads the entire response body into memory (up to 10MB)
// so it can be scored before forwarding. Returns the logged portion for audit,
// the full body for forwarding, and the total size.
func BufferResponseBody(body io.ReadCloser, contentType string, limits BodyLimits) (*BufferedResponse, error) {
	defer body.Close()

	fullBody, err := io.ReadAll(io.LimitReader(body, maxResponseBuffer))
	if err != nil {
		return nil, err
	}

	isBin := isBinaryContentType(contentType)
	logLimit := limits.MaxTextLog
	if isBin {
		logLimit = limits.MaxBinaryLog
	}

	logged := fullBody
	if len(logged) > logLimit {
		logged = logged[:logLimit]
	}

	return &BufferedResponse{
		Logged:   logged,
		FullBody: fullBody,
		FullSize: int64(len(fullBody)),
		IsBinary: isBin,
	}, nil
}

// isBinaryContent checks Content-Type and falls back to content sniffing.
func isBinaryContent(contentType string, data []byte) bool {
	if isBinaryContentType(contentType) {
		return true
	}
	if isTextContentType(contentType) {
		return false
	}
	// Content-Type inconclusive — sniff the data.
	if len(data) == 0 {
		return false
	}
	detected := http.DetectContentType(data)
	return !strings.HasPrefix(detected, "text/")
}

// isBinaryContentType returns true if the Content-Type header indicates binary content.
func isBinaryContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(ct)
	mediaType = strings.ToLower(mediaType)
	switch {
	case strings.HasPrefix(mediaType, "image/"),
		strings.HasPrefix(mediaType, "audio/"),
		strings.HasPrefix(mediaType, "video/"),
		mediaType == "application/octet-stream",
		mediaType == "application/zip",
		mediaType == "application/gzip",
		mediaType == "application/pdf":
		return true
	}
	return false
}

// isTextContentType returns true if the Content-Type header indicates text content.
func isTextContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(ct)
	mediaType = strings.ToLower(mediaType)
	switch {
	case strings.HasPrefix(mediaType, "text/"),
		mediaType == "application/json",
		mediaType == "application/xml",
		strings.HasSuffix(mediaType, "+json"),
		strings.HasSuffix(mediaType, "+xml"):
		return true
	}
	return false
}
