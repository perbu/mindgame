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
