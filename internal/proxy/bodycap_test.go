package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestResponseCapture_SmallBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader("hello world"))
	cap := newResponseCapture(body, 1024)

	var dst bytes.Buffer
	n, err := io.Copy(&dst, cap)
	if err != nil {
		t.Fatal(err)
	}
	cap.Close()

	if n != 11 {
		t.Errorf("bytes read = %d, want 11", n)
	}
	if dst.String() != "hello world" {
		t.Errorf("dst = %q, want %q", dst.String(), "hello world")
	}
	if string(cap.Logged()) != "hello world" {
		t.Errorf("logged = %q, want %q", string(cap.Logged()), "hello world")
	}
	if cap.FullSize() != 11 {
		t.Errorf("full size = %d, want 11", cap.FullSize())
	}
}

func TestResponseCapture_ExceedsLimit(t *testing.T) {
	data := strings.Repeat("x", 200)
	body := io.NopCloser(strings.NewReader(data))
	cap := newResponseCapture(body, 50)

	var dst bytes.Buffer
	n, err := io.Copy(&dst, cap)
	if err != nil {
		t.Fatal(err)
	}
	cap.Close()

	// All data should pass through to dst.
	if int(n) != 200 {
		t.Errorf("bytes read = %d, want 200", n)
	}
	if dst.String() != data {
		t.Errorf("dst length = %d, want 200", dst.Len())
	}
	// Only the first 50 bytes should be captured.
	if len(cap.Logged()) != 50 {
		t.Errorf("logged length = %d, want 50", len(cap.Logged()))
	}
	if cap.FullSize() != 200 {
		t.Errorf("full size = %d, want 200", cap.FullSize())
	}
}

func TestCaptureResponseBody(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		wantLogged  int // expected logged length
	}{
		{
			name:        "text body under limit",
			body:        "short text response",
			contentType: "application/json",
			wantLogged:  19,
		},
		{
			name:        "binary content type uses binary limit",
			body:        strings.Repeat("x", 100),
			contentType: "image/png",
			wantLogged:  64, // capped at MaxBinaryLog
		},
	}

	limits := BodyLimits{MaxTextLog: 1024, MaxBinaryLog: 64}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader(tt.body))
			var dst bytes.Buffer
			logged, fullSize, err := CaptureResponseBody(body, tt.contentType, limits, &dst)
			if err != nil {
				t.Fatal(err)
			}
			if int(fullSize) != len(tt.body) {
				t.Errorf("fullSize = %d, want %d", fullSize, len(tt.body))
			}
			if len(logged) != tt.wantLogged {
				t.Errorf("logged length = %d, want %d", len(logged), tt.wantLogged)
			}
			if dst.String() != tt.body {
				t.Errorf("dst = %q, want %q", dst.String(), tt.body)
			}
		})
	}
}

func TestResponseCaptureLimit(t *testing.T) {
	limits := BodyLimits{MaxTextLog: 1000, MaxBinaryLog: 64}

	if got := ResponseCaptureLimit("text/html", limits); got != 1000 {
		t.Errorf("text limit = %d, want 1000", got)
	}
	if got := ResponseCaptureLimit("application/json", limits); got != 1000 {
		t.Errorf("json limit = %d, want 1000", got)
	}
	if got := ResponseCaptureLimit("image/png", limits); got != 64 {
		t.Errorf("image limit = %d, want 64", got)
	}
	if got := ResponseCaptureLimit("application/octet-stream", limits); got != 64 {
		t.Errorf("octet-stream limit = %d, want 64", got)
	}
	// Empty content type defaults to text limit.
	if got := ResponseCaptureLimit("", limits); got != 1000 {
		t.Errorf("empty limit = %d, want 1000", got)
	}
}
