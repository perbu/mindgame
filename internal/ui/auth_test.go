package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthRedirectsUnauthenticated(t *testing.T) {
	srv := setupTestServer(t)

	for _, path := range []string{"/", "/domains", "/scoring", "/stats"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET %s: status = %d, want %d", path, rec.Code, http.StatusSeeOther)
		}
		loc := rec.Header().Get("Location")
		if loc != "/auth" {
			t.Errorf("GET %s: Location = %q, want /auth", path, loc)
		}
	}
}

func TestAuthPageRendersWhenUnauthenticated(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/auth", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Generate Login Code") {
		t.Error("missing Generate Login Code button")
	}
}

func TestAuthPageRedirectsWhenAuthenticated(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/auth", nil)
	addAuthCookie(srv, req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

func TestAuthChallengeReturnsForm(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("POST", "/auth/challenge", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "check your server logs") {
		t.Error("missing log hint text")
	}
	if !strings.Contains(body, `name="code"`) {
		t.Error("missing code input field")
	}
}

func TestAuthVerifyCorrectCode(t *testing.T) {
	srv := setupTestServer(t)

	// Generate a challenge.
	code := srv.auth.newChallenge()

	// Submit the correct code.
	form := url.Values{"code": {code}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Should set HX-Redirect header.
	if hxr := rec.Header().Get("HX-Redirect"); hxr != "/" {
		t.Errorf("HX-Redirect = %q, want /", hxr)
	}
	// Should set session cookie.
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == cookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing session cookie")
	}
}

func TestAuthVerifyCaseInsensitive(t *testing.T) {
	srv := setupTestServer(t)

	code := srv.auth.newChallenge()

	form := url.Values{"code": {strings.ToLower(code)}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if hxr := rec.Header().Get("HX-Redirect"); hxr != "/" {
		t.Errorf("lowercase code should be accepted, HX-Redirect = %q", hxr)
	}
}

func TestAuthVerifyWrongCode(t *testing.T) {
	srv := setupTestServer(t)

	srv.auth.newChallenge()

	form := url.Values{"code": {"ZZZZZZ"}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Invalid or expired") {
		t.Error("expected error message for wrong code")
	}
	// Should not set session cookie.
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			t.Error("session cookie should not be set for wrong code")
		}
	}
}

func TestAuthVerifyExpiredChallenge(t *testing.T) {
	srv := setupTestServer(t)

	srv.auth.newChallenge()

	// Expire the challenge manually.
	srv.auth.mu.Lock()
	code := srv.auth.challenge
	srv.auth.expiresAt = time.Now().Add(-1 * time.Second)
	srv.auth.mu.Unlock()

	form := url.Values{"code": {code}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Invalid or expired") {
		t.Error("expected error message for expired challenge")
	}
}

func TestAuthVerifyCodeConsumedOnUse(t *testing.T) {
	srv := setupTestServer(t)

	code := srv.auth.newChallenge()

	// First attempt — should succeed.
	form := url.Values{"code": {code}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Header().Get("HX-Redirect") != "/" {
		t.Fatal("first verify should succeed")
	}

	// Second attempt with same code — should fail.
	req = httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Header().Get("HX-Redirect") == "/" {
		t.Error("replayed code should not be accepted")
	}
}

func TestAuthVerifyNoChallenge(t *testing.T) {
	srv := setupTestServer(t)

	// Submit without ever generating a challenge.
	form := url.Values{"code": {"ABCDEF"}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Invalid or expired") {
		t.Error("expected error when no challenge was generated")
	}
}

func TestAuthCookieFromDifferentKeyRejected(t *testing.T) {
	srv := setupTestServer(t)

	// Create a cookie signed by a different Auth instance.
	other := NewAuth()
	rec := httptest.NewRecorder()
	other.setSessionCookie(rec)

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("foreign cookie should be rejected, status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestAuthNewChallengeOverwritesPrevious(t *testing.T) {
	srv := setupTestServer(t)

	first := srv.auth.newChallenge()
	second := srv.auth.newChallenge()

	if first == second {
		t.Skip("codes happened to match (extremely unlikely)")
	}

	// Old code should fail.
	form := url.Values{"code": {first}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Header().Get("HX-Redirect") == "/" {
		t.Error("old challenge code should be rejected after new one generated")
	}

	// New code should succeed.
	form = url.Values{"code": {second}}
	req = httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Header().Get("HX-Redirect") != "/" {
		t.Error("current challenge code should be accepted")
	}
}
