package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/perbu/mindgame/internal/db"
)

func openTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestEvaluateAllow(t *testing.T) {
	store := openTestStore(t)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: "allowed.com", Tier: "allow", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	d := c.Evaluate("allowed.com")
	if d.Tier != TierAllow {
		t.Errorf("tier = %q, want %q", d.Tier, TierAllow)
	}
	if d.RequireReason {
		t.Error("RequireReason should be false for allow tier")
	}
}

func TestEvaluateDeny(t *testing.T) {
	store := openTestStore(t)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: "evil.com", Tier: "deny", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	d := c.Evaluate("evil.com")
	if d.Tier != TierDeny {
		t.Errorf("tier = %q, want %q", d.Tier, TierDeny)
	}
	if d.RequireReason {
		t.Error("RequireReason should be false for deny tier")
	}
}

func TestEvaluateDefault(t *testing.T) {
	store := openTestStore(t)
	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	d := c.Evaluate("unknown.com")
	if d.Tier != TierDefault {
		t.Errorf("tier = %q, want %q", d.Tier, TierDefault)
	}
	if !d.RequireReason {
		t.Error("RequireReason should be true for default tier")
	}
}

func TestEvaluateCaseInsensitive(t *testing.T) {
	store := openTestStore(t)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: "example.com", Tier: "allow", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	d := c.Evaluate("EXAMPLE.COM")
	if d.Tier != TierAllow {
		t.Errorf("tier = %q, want %q", d.Tier, TierAllow)
	}
}

func TestCacheReload(t *testing.T) {
	store := openTestStore(t)
	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// Initially unknown.
	d := c.Evaluate("new.com")
	if d.Tier != TierDefault {
		t.Errorf("before reload: tier = %q, want %q", d.Tier, TierDefault)
	}

	// Insert rule and reload.
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: "new.com", Tier: "deny", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}

	d = c.Evaluate("new.com")
	if d.Tier != TierDeny {
		t.Errorf("after reload: tier = %q, want %q", d.Tier, TierDeny)
	}
}

func TestStopDoubleCallNoPanic(t *testing.T) {
	store := openTestStore(t)
	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.Stop()
	c.Stop() // second call should not panic
}

func TestEvaluateWildcard(t *testing.T) {
	store := openTestStore(t)
	if err := store.InsertDomainRule(&db.DomainRule{
		Host: "*.slack.com", Tier: "allow", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// Subdomain should match.
	d := c.Evaluate("api.slack.com")
	if d.Tier != TierAllow {
		t.Errorf("api.slack.com: tier = %q, want %q", d.Tier, TierAllow)
	}
	d = c.Evaluate("hooks.slack.com")
	if d.Tier != TierAllow {
		t.Errorf("hooks.slack.com: tier = %q, want %q", d.Tier, TierAllow)
	}

	// Bare domain should NOT match the wildcard.
	d = c.Evaluate("slack.com")
	if d.Tier != TierDefault {
		t.Errorf("slack.com: tier = %q, want %q", d.Tier, TierDefault)
	}

	// Unrelated domain should not match.
	d = c.Evaluate("notslack.com")
	if d.Tier != TierDefault {
		t.Errorf("notslack.com: tier = %q, want %q", d.Tier, TierDefault)
	}
}

func TestEvaluateExactOverridesWildcard(t *testing.T) {
	store := openTestStore(t)
	now := time.Now()
	if err := store.InsertDomainRules([]db.DomainRule{
		{Host: "*.example.com", Tier: "allow", CreatedAt: now},
		{Host: "bad.example.com", Tier: "deny", CreatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// Exact deny should win over wildcard allow.
	d := c.Evaluate("bad.example.com")
	if d.Tier != TierDeny {
		t.Errorf("bad.example.com: tier = %q, want %q", d.Tier, TierDeny)
	}

	// Other subdomains should still match the wildcard.
	d = c.Evaluate("good.example.com")
	if d.Tier != TierAllow {
		t.Errorf("good.example.com: tier = %q, want %q", d.Tier, TierAllow)
	}
}

func TestValidateHost(t *testing.T) {
	valid := []string{
		"example.com",
		"api.slack.com",
		"*.slack.com",
		"*.sub.example.com",
	}
	for _, h := range valid {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) = %v, want nil", h, err)
		}
	}

	invalid := []string{
		"",
		"*.",          // no suffix
		"*.*.com",     // double wildcard
		"foo.*.com",   // mid-string wildcard
		"..com",       // consecutive dots
		".example.com", // leading dot
	}
	for _, h := range invalid {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want error", h)
		}
	}
}

func TestParseSeedFileWildcard(t *testing.T) {
	content := "allow *.slack.com  # Slack APIs\ndeny *.evil.com\n"
	path := filepath.Join(t.TempDir(), "seed.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := ParseSeedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Host != "*.slack.com" || rules[0].Tier != "allow" {
		t.Errorf("rule 0 = %+v", rules[0])
	}
}

func TestParseSeedFile(t *testing.T) {
	content := `# This is a comment
allow api.anthropic.com   # Anthropic API
deny evil.example.com     # Known bad

allow good.example.com
`
	path := filepath.Join(t.TempDir(), "seed.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := ParseSeedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	if rules[0].Host != "api.anthropic.com" || rules[0].Tier != "allow" || rules[0].Note != "Anthropic API" {
		t.Errorf("rule 0 = %+v", rules[0])
	}
	if rules[1].Host != "evil.example.com" || rules[1].Tier != "deny" || rules[1].Note != "Known bad" {
		t.Errorf("rule 1 = %+v", rules[1])
	}
	if rules[2].Host != "good.example.com" || rules[2].Tier != "allow" || rules[2].Note != "" {
		t.Errorf("rule 2 = %+v", rules[2])
	}
}

func TestParseSeedFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"invalid tier", "block evil.com\n"},
		{"malformed line", "allow\n"},
		{"too many fields", "allow a.com b.com\n"},
		{"invalid wildcard", "allow *.*.com\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.txt")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := ParseSeedFile(path)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
