package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCreatesSchema(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// Verify tables exist by querying them.
	for _, table := range []string{"audit_log", "domain_rules", "scoring_rules"} {
		var name string
		err := store.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestInsertAndListAuditEntries(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	entry := &AuditEntry{
		Timestamp:   now,
		Method:      "GET",
		URL:         "http://example.com/path",
		Host:        "example.com",
		Reason:      "testing",
		ReqHeaders:  `{"Accept":["*/*"]}`,
		ReqBody:     "",
		RespStatus:  200,
		RespBody:    "OK",
		RiskScore:   0,
		RiskSignals: "[]",
		Action:      "ALLOW",
	}

	if err := store.InsertAuditEntry(entry); err != nil {
		t.Fatalf("InsertAuditEntry: %v", err)
	}
	if entry.ID == 0 {
		t.Fatal("expected non-zero ID after insert")
	}

	entries, err := store.ListAuditEntries(10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got := entries[0]
	if got.Method != "GET" {
		t.Errorf("method = %q, want %q", got.Method, "GET")
	}
	if got.URL != "http://example.com/path" {
		t.Errorf("url = %q, want %q", got.URL, "http://example.com/path")
	}
	if got.Host != "example.com" {
		t.Errorf("host = %q, want %q", got.Host, "example.com")
	}
	if got.Action != "ALLOW" {
		t.Errorf("action = %q, want %q", got.Action, "ALLOW")
	}
	if got.RespStatus != 200 {
		t.Errorf("resp_status = %d, want %d", got.RespStatus, 200)
	}
}

func TestInsertAndLookupDomainRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	r := &DomainRule{
		Host:      "example.com",
		Tier:      "allow",
		Banned:    false,
		CreatedAt: now,
		Note:      "test rule",
	}
	if err := store.InsertDomainRule(r); err != nil {
		t.Fatalf("InsertDomainRule: %v", err)
	}

	got, err := store.LookupDomainRule("example.com")
	if err != nil {
		t.Fatalf("LookupDomainRule: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil rule")
	}
	if got.Host != "example.com" {
		t.Errorf("host = %q, want %q", got.Host, "example.com")
	}
	if got.Tier != "allow" {
		t.Errorf("tier = %q, want %q", got.Tier, "allow")
	}
	if got.Note != "test rule" {
		t.Errorf("note = %q, want %q", got.Note, "test rule")
	}
}

func TestLookupDomainRuleMissing(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	got, err := store.LookupDomainRule("nonexistent.com")
	if err != nil {
		t.Fatalf("LookupDomainRule: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestInsertDomainRuleUpsert(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	r := &DomainRule{Host: "example.com", Tier: "allow", CreatedAt: now}
	if err := store.InsertDomainRule(r); err != nil {
		t.Fatalf("InsertDomainRule: %v", err)
	}

	// Upsert with different tier.
	r2 := &DomainRule{Host: "example.com", Tier: "deny", CreatedAt: now, Note: "updated"}
	if err := store.InsertDomainRule(r2); err != nil {
		t.Fatalf("InsertDomainRule (upsert): %v", err)
	}

	got, err := store.LookupDomainRule("example.com")
	if err != nil {
		t.Fatalf("LookupDomainRule: %v", err)
	}
	if got.Tier != "deny" {
		t.Errorf("tier = %q, want %q", got.Tier, "deny")
	}
	if got.Note != "updated" {
		t.Errorf("note = %q, want %q", got.Note, "updated")
	}
}

func TestInsertDomainRulesBatch(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	rules := []DomainRule{
		{Host: "a.com", Tier: "allow", CreatedAt: now},
		{Host: "b.com", Tier: "deny", CreatedAt: now},
		{Host: "c.com", Tier: "allow", CreatedAt: now},
	}
	if err := store.InsertDomainRules(rules); err != nil {
		t.Fatalf("InsertDomainRules: %v", err)
	}

	all, err := store.ListDomainRules()
	if err != nil {
		t.Fatalf("ListDomainRules: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}
}

func TestInsertAndListScoringRules(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	rules := []ScoringRule{
		{Name: "rule_c", Expr: `method == "GET"`, Points: 3, Enabled: true, Note: "get check"},
		{Name: "rule_a", Expr: `body_size > 100`, Points: 5, Enabled: false, Note: ""},
		{Name: "rule_b", Expr: `host == "evil.com"`, Points: 10, Enabled: true, Note: "evil"},
	}
	if err := store.InsertScoringRules(rules); err != nil {
		t.Fatalf("InsertScoringRules: %v", err)
	}

	got, err := store.ListScoringRules()
	if err != nil {
		t.Fatalf("ListScoringRules: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(got))
	}
	// Ordered by name.
	if got[0].Name != "rule_a" {
		t.Errorf("first name = %q, want %q", got[0].Name, "rule_a")
	}
	if got[1].Name != "rule_b" {
		t.Errorf("second name = %q, want %q", got[1].Name, "rule_b")
	}
	if got[2].Name != "rule_c" {
		t.Errorf("third name = %q, want %q", got[2].Name, "rule_c")
	}
	// Verify fields on one rule.
	if got[2].Points != 3 {
		t.Errorf("rule_c points = %d, want 3", got[2].Points)
	}
	if !got[2].Enabled {
		t.Error("rule_c should be enabled")
	}
	if got[2].Note != "get check" {
		t.Errorf("rule_c note = %q, want %q", got[2].Note, "get check")
	}

	count, err := store.CountScoringRules()
	if err != nil {
		t.Fatalf("CountScoringRules: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestCountScoringRulesEmpty(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	count, err := store.CountScoringRules()
	if err != nil {
		t.Fatalf("CountScoringRules: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestCountScoringRulesAfterInsert(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	rules := []ScoringRule{
		{Name: "r1", Expr: `true`, Points: 1, Enabled: true},
		{Name: "r2", Expr: `false`, Points: 2, Enabled: true},
	}
	if err := store.InsertScoringRules(rules); err != nil {
		t.Fatalf("InsertScoringRules: %v", err)
	}

	count, err := store.CountScoringRules()
	if err != nil {
		t.Fatalf("CountScoringRules: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestListDomainRules(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	rules := []DomainRule{
		{Host: "z.com", Tier: "deny", CreatedAt: now},
		{Host: "a.com", Tier: "allow", CreatedAt: now},
		{Host: "m.com", Tier: "deny", CreatedAt: now, Note: "middle"},
	}
	if err := store.InsertDomainRules(rules); err != nil {
		t.Fatalf("InsertDomainRules: %v", err)
	}

	all, err := store.ListDomainRules()
	if err != nil {
		t.Fatalf("ListDomainRules: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}
	// Ordered by host.
	if all[0].Host != "a.com" {
		t.Errorf("first host = %q, want %q", all[0].Host, "a.com")
	}
	if all[1].Host != "m.com" {
		t.Errorf("second host = %q, want %q", all[1].Host, "m.com")
	}
	if all[2].Host != "z.com" {
		t.Errorf("third host = %q, want %q", all[2].Host, "z.com")
	}
}
