package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
	"github.com/perbu/mindgame/internal/scoring"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	pol, err := policy.NewCache(store, time.Hour)
	if err != nil {
		t.Fatalf("policy.NewCache: %v", err)
	}
	t.Cleanup(pol.Stop)

	broker := NewBroker()

	reloadScorer := func() error {
		rules, err := store.ListScoringRules()
		if err != nil {
			return err
		}
		_, err = scoring.New(rules)
		return err
	}

	reloadRespScorer := func() error {
		rules, err := store.ListResponseScoringRules()
		if err != nil {
			return err
		}
		_, err = scoring.NewResponse(rules)
		return err
	}

	return NewServer(store, pol, reloadScorer, reloadRespScorer, broker)
}

func TestFeedPage(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Live Feed") {
		t.Error("missing Live Feed heading")
	}
	if !strings.Contains(body, "htmx.min.js") {
		t.Error("missing htmx script reference")
	}
}

func TestDomainsPage(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/domains", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Domain Rules") {
		t.Error("missing Domain Rules heading")
	}
}

func TestDomainCRUD(t *testing.T) {
	srv := setupTestServer(t)

	// Create.
	form := url.Values{"host": {"test.com"}, "tier": {"allow"}, "note": {"test"}}
	req := httptest.NewRequest("POST", "/domains", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test.com") {
		t.Error("response missing created domain")
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/domains/test.com", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "test.com") {
		t.Error("response still contains deleted domain")
	}
}

func TestScoringPage(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/scoring", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Scoring Rules") {
		t.Error("missing Scoring Rules heading")
	}
}

func TestScoringCRUD(t *testing.T) {
	srv := setupTestServer(t)

	// Create.
	form := url.Values{"name": {"test_rule"}, "expr": {"true"}, "points": {"5"}, "note": {"test"}}
	req := httptest.NewRequest("POST", "/scoring", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test_rule") {
		t.Error("response missing created rule")
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/scoring/test_rule", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", rec.Code)
	}
}

func TestScoringTest(t *testing.T) {
	srv := setupTestServer(t)

	// Insert a rule first.
	if err := srv.store.InsertScoringRule(&db.ScoringRule{
		Name: "always_on", Expr: "true", Points: 3, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"method": {"GET"},
		"url":    {"http://example.com/test"},
		"reason": {"test"},
		"body":   {""},
	}
	req := httptest.NewRequest("POST", "/scoring/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "3") {
		t.Error("expected score of 3 in output")
	}
	if !strings.Contains(body, "always_on") {
		t.Error("expected always_on signal")
	}
}

func TestStatsPage(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/stats", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Statistics") {
		t.Error("missing Statistics heading")
	}
}

func TestStatsData(t *testing.T) {
	srv := setupTestServer(t)

	// Seed some data.
	if err := srv.store.InsertAuditEntry(&db.AuditEntry{
		Timestamp: time.Now(), Method: "GET", URL: "http://test.com",
		Host: "test.com", Action: "ALLOW", RiskSignals: "[]",
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/stats/data", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test.com") {
		t.Error("missing host in stats data")
	}
}

func TestStaticAssets(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/static/style.css", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "--bg:") {
		t.Error("CSS file not served correctly")
	}
}

func TestFeedSSE(t *testing.T) {
	srv := setupTestServer(t)

	// Use a real HTTP server because SSE requires http.Flusher.
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Publish an entry before connecting — that way when the subscriber
	// reads, it will be queued in the channel already.
	go func() {
		// Small delay so the client has time to connect and subscribe.
		time.Sleep(100 * time.Millisecond)
		srv.broker.Publish(&db.AuditEntry{
			ID: 99, Timestamp: time.Now(), Method: "GET",
			URL: "http://x.com", Host: "x.com", Action: "ALLOW",
			RiskSignals: "[]",
		})
	}()

	// Use a transport that doesn't buffer the whole response.
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/feed/events", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	// Read some data from the stream.
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "data:") {
		t.Errorf("SSE body missing data field, got: %q", body)
	}
}

func TestDreamPage(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/dream", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<canvas") {
		t.Error("missing <canvas> element")
	}
}

func TestDreamSSE(t *testing.T) {
	srv := setupTestServer(t)

	ts := httptest.NewServer(srv)
	defer ts.Close()

	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.broker.Publish(&db.AuditEntry{
			ID: 42, Timestamp: time.Now(), Method: "POST",
			URL: "http://evil.com/hack", Host: "evil.com", Action: "BAN",
			RiskScore: 25, RiskSignals: `["suspicious_path","large_body"]`,
			ReqBody: []byte("payload-data"), ReqBodySize: 12,
		})
	}()

	client := &http.Client{
		Transport: &http.Transport{DisableCompression: true},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/dream/events", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "event: audit") {
		t.Errorf("missing event type, got: %q", body)
	}
	if !strings.Contains(body, `"host":"evil.com"`) {
		t.Errorf("missing host field, got: %q", body)
	}
	if !strings.Contains(body, `"action":"BAN"`) {
		t.Errorf("missing action field, got: %q", body)
	}
	if !strings.Contains(body, `"score":25`) {
		t.Errorf("missing score field, got: %q", body)
	}
	if !strings.Contains(body, `"bodySize":12`) {
		t.Errorf("missing/wrong bodySize, got: %q", body)
	}
	if !strings.Contains(body, `"suspicious_path"`) {
		t.Errorf("missing signals, got: %q", body)
	}
}

func TestRespScoringCRUD(t *testing.T) {
	srv := setupTestServer(t)

	// Create.
	form := url.Values{"name": {"resp_rule"}, "expr": {"true"}, "points": {"5"}, "note": {"test resp"}}
	req := httptest.NewRequest("POST", "/scoring/response", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "resp_rule") {
		t.Error("response missing created rule")
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/scoring/response/resp_rule", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", rec.Code)
	}
}

func TestRespScoringCreateInvalid(t *testing.T) {
	srv := setupTestServer(t)

	tests := []struct {
		name string
		form url.Values
	}{
		{"missing name", url.Values{"expr": {"true"}, "points": {"5"}}},
		{"missing expr", url.Values{"name": {"r1"}, "points": {"5"}}},
		{"bad points", url.Values{"name": {"r1"}, "expr": {"true"}, "points": {"abc"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/scoring/response", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestRespScoringUpdate(t *testing.T) {
	srv := setupTestServer(t)

	// Seed a rule.
	if err := srv.store.InsertResponseScoringRule(&db.ScoringRule{
		Name: "resp_r1", Expr: "true", Points: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"expr": {"false"}, "points": {"10"}, "enabled": {"false"}, "note": {"updated"}}
	req := httptest.NewRequest("PUT", "/scoring/response/resp_r1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200", rec.Code)
	}
}

func TestRespScoringUpdateInvalidPoints(t *testing.T) {
	srv := setupTestServer(t)

	form := url.Values{"expr": {"true"}, "points": {"abc"}, "note": {""}}
	req := httptest.NewRequest("PUT", "/scoring/response/whatever", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRespScoringTest(t *testing.T) {
	srv := setupTestServer(t)

	// Insert a response scoring rule.
	if err := srv.store.InsertResponseScoringRule(&db.ScoringRule{
		Name: "always_match", Expr: "true", Points: 7, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"status_code":  {"200"},
		"body":         {"some body"},
		"content_type": {"text/html"},
		"host":         {"example.com"},
	}
	req := httptest.NewRequest("POST", "/scoring/response/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "7") {
		t.Error("expected score of 7 in output")
	}
	if !strings.Contains(body, "always_match") {
		t.Error("expected always_match signal")
	}
}

func TestDomainUpdate(t *testing.T) {
	srv := setupTestServer(t)

	// Seed a domain.
	if err := srv.store.InsertDomainRule(&db.DomainRule{
		Host: "update.com", Tier: "allow", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"tier": {"deny"}, "banned": {"true"}, "note": {"banned now"}}
	req := httptest.NewRequest("PUT", "/domains/update.com", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestScoringUpdate(t *testing.T) {
	srv := setupTestServer(t)

	// Seed a scoring rule.
	if err := srv.store.InsertScoringRule(&db.ScoringRule{
		Name: "upd_rule", Expr: "true", Points: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"expr": {"false"}, "points": {"20"}, "enabled": {"false"}, "note": {"changed"}}
	req := httptest.NewRequest("PUT", "/scoring/upd_rule", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestFeedDetail(t *testing.T) {
	srv := setupTestServer(t)

	entry := &db.AuditEntry{
		Timestamp: time.Now(), Method: "POST", URL: "http://example.com/api",
		Host: "example.com", Action: "BLOCK", RiskScore: 15,
		RiskSignals: `["rule1"]`, ReqHeaders: `{"X-Reason":["test"]}`,
		Reason: "test detail",
	}
	if err := srv.store.InsertAuditEntry(entry); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/feed/detail/1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test detail") {
		t.Error("missing reason in detail")
	}
}
