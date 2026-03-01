package ui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/perbu/mindgame/internal/ui/templates"
)

const (
	cookieName    = "mg_session"
	cookieMaxAge  = 100 * 24 * time.Hour // 100 days
	challengeTTL  = 30 * time.Second
	challengeLen  = 6
	challengePool = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1 to avoid confusion
)

// Auth handles UI authentication via a one-time challenge code.
type Auth struct {
	hmacKey []byte

	mu        sync.Mutex
	challenge string
	expiresAt time.Time
}

// NewAuth creates an Auth with a random HMAC key.
func NewAuth() *Auth {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("ui.NewAuth: crypto/rand: %v", err))
	}
	return &Auth{hmacKey: key}
}

// RequireAuth returns middleware that redirects unauthenticated requests to /auth.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.validCookie(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
	})
}

// HandleAuth renders the login page.
func (a *Auth) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if a.validCookie(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.AuthPage().Render(r.Context(), w)
}

// HandleChallenge generates a one-time code, logs it, and returns the verify form.
func (a *Auth) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	code := a.newChallenge()
	slog.Warn("UI login code generated — enter within 30s", "code", code)
	templates.AuthChallengeForm().Render(r.Context(), w)
}

// HandleVerify checks the submitted code and sets a session cookie on success.
func (a *Auth) HandleVerify(w http.ResponseWriter, r *http.Request) {
	submitted := strings.TrimSpace(r.FormValue("code"))

	a.mu.Lock()
	valid := a.challenge != "" &&
		time.Now().Before(a.expiresAt) &&
		strings.EqualFold(submitted, a.challenge)
	if valid {
		a.challenge = ""
	}
	a.mu.Unlock()

	if !valid {
		templates.AuthError("Invalid or expired code.").Render(r.Context(), w)
		return
	}

	slog.Info("UI login successful")
	a.setSessionCookie(w)
	w.Header().Set("HX-Redirect", "/")
}

// newChallenge generates a random code and stores it with a TTL.
func (a *Auth) newChallenge() string {
	b := make([]byte, challengeLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("ui.newChallenge: crypto/rand: %v", err))
	}
	code := make([]byte, challengeLen)
	for i := range code {
		code[i] = challengePool[int(b[i])%len(challengePool)]
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.challenge = string(code)
	a.expiresAt = time.Now().Add(challengeTTL)
	return a.challenge
}

// setSessionCookie writes an HMAC-signed cookie with an embedded expiry.
func (a *Auth) setSessionCookie(w http.ResponseWriter) {
	expires := time.Now().Add(cookieMaxAge)
	ts := strconv.FormatInt(expires.Unix(), 10)
	sig := a.sign(ts)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    ts + "|" + sig,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// validCookie checks whether the request carries a valid session cookie.
func (a *Auth) validCookie(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, "|", 2)
	if len(parts) != 2 {
		return false
	}
	ts, sig := parts[0], parts[1]

	// Verify HMAC.
	if !hmac.Equal([]byte(a.sign(ts)), []byte(sig)) {
		return false
	}

	// Check expiry.
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(unix, 0))
}

// sign returns a hex-encoded HMAC-SHA256 of the given message.
func (a *Auth) sign(msg string) string {
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
