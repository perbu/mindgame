package db

import (
	"path/filepath"
	"reflect"
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
		ReqBody:     nil,
		RespStatus:  200,
		RespBody:    []byte("OK"),
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
	// List queries omit bodies.
	if got.ReqBody != nil {
		t.Errorf("ReqBody should be nil in list query, got %d bytes", len(got.ReqBody))
	}
	if got.RespBody != nil {
		t.Errorf("RespBody should be nil in list query, got %d bytes", len(got.RespBody))
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

func TestUpdateDomainRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	if err := store.InsertDomainRule(&DomainRule{Host: "example.com", Tier: "allow", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateDomainRule("example.com", "deny", true, "banned now"); err != nil {
		t.Fatal(err)
	}

	got, err := store.LookupDomainRule("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != "deny" {
		t.Errorf("tier = %q, want deny", got.Tier)
	}
	if !got.Banned {
		t.Error("expected banned=true")
	}
	if got.Note != "banned now" {
		t.Errorf("note = %q, want %q", got.Note, "banned now")
	}
}

func TestUpdateDomainRuleNotFound(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.UpdateDomainRule("nonexistent.com", "allow", false, ""); err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestDeleteDomainRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	if err := store.InsertDomainRule(&DomainRule{Host: "example.com", Tier: "allow", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteDomainRule("example.com"); err != nil {
		t.Fatal(err)
	}

	got, err := store.LookupDomainRule("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

func TestDeleteDomainRuleNotFound(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.DeleteDomainRule("nonexistent.com"); err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestListDomainRulesFiltered(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now().Truncate(time.Second)
	rules := []DomainRule{
		{Host: "example.com", Tier: "allow", CreatedAt: now},
		{Host: "evil.com", Tier: "deny", Banned: true, CreatedAt: now},
		{Host: "test.example.com", Tier: "allow", CreatedAt: now},
	}
	if err := store.InsertDomainRules(rules); err != nil {
		t.Fatal(err)
	}

	// Filter by "example" should return 2 rules.
	got, err := store.ListDomainRulesFiltered("example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(got))
	}

	// Empty filter should return all, banned first.
	got, err = store.ListDomainRulesFiltered("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(got))
	}
	if got[0].Host != "evil.com" {
		t.Errorf("first host = %q, want evil.com (banned first)", got[0].Host)
	}
}

func TestInsertScoringRuleSingle(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	r := &ScoringRule{Name: "test_rule", Expr: `method == "GET"`, Points: 5, Enabled: true, Note: "test"}
	if err := store.InsertScoringRule(r); err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "test_rule" {
		t.Errorf("name = %q, want test_rule", rules[0].Name)
	}
}

func TestUpdateScoringRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.InsertScoringRule(&ScoringRule{Name: "r1", Expr: "true", Points: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateScoringRule("r1", "false", 10, false, "updated"); err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Expr != "false" {
		t.Errorf("expr = %q, want false", rules[0].Expr)
	}
	if rules[0].Points != 10 {
		t.Errorf("points = %d, want 10", rules[0].Points)
	}
	if rules[0].Enabled {
		t.Error("expected enabled=false")
	}
	if rules[0].Note != "updated" {
		t.Errorf("note = %q, want updated", rules[0].Note)
	}
}

func TestUpdateScoringRuleNotFound(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.UpdateScoringRule("nonexistent", "true", 1, true, ""); err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestDeleteScoringRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.InsertScoringRule(&ScoringRule{Name: "r1", Expr: "true", Points: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteScoringRule("r1"); err != nil {
		t.Fatal(err)
	}

	count, err := store.CountScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestGetAuditEntry(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	entry := &AuditEntry{
		Timestamp: time.Now(), Method: "GET", URL: "http://example.com",
		Host: "example.com", Action: "ALLOW", RiskSignals: "[]",
	}
	if err := store.InsertAuditEntry(entry); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetAuditEntry(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Method != "GET" {
		t.Errorf("method = %q, want GET", got.Method)
	}

	// Missing entry.
	got, err = store.GetAuditEntry(9999)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil for missing entry, got %+v", got)
	}
}

func TestListAuditEntriesFiltered(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now()
	entries := []*AuditEntry{
		{Timestamp: now, Method: "GET", URL: "http://a.com/1", Host: "a.com", Action: "ALLOW", RiskScore: 0, RiskSignals: "[]"},
		{Timestamp: now, Method: "POST", URL: "http://b.com/2", Host: "b.com", Action: "BLOCK", RiskScore: 12, RiskSignals: `["rule1"]`},
		{Timestamp: now, Method: "GET", URL: "http://a.com/3", Host: "a.com", Action: "DENY", RiskScore: 0, RiskSignals: "[]"},
	}
	for _, e := range entries {
		if err := store.InsertAuditEntry(e); err != nil {
			t.Fatal(err)
		}
	}

	// Filter by action.
	got, err := store.ListAuditEntriesFiltered(AuditFilter{Action: "BLOCK"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Action != "BLOCK" {
		t.Errorf("action = %q, want BLOCK", got[0].Action)
	}

	// Filter by host.
	got, err = store.ListAuditEntriesFiltered(AuditFilter{Host: "a.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}

	// Filter by min score.
	got, err = store.ListAuditEntriesFiltered(AuditFilter{MinScore: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}

	// Cursor-based pagination.
	got, err = store.ListAuditEntriesFiltered(AuditFilter{AfterID: entries[2].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestGetAuditStats(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now()
	entries := []*AuditEntry{
		{Timestamp: now, Method: "GET", URL: "http://a.com/1", Host: "a.com", Action: "ALLOW", RiskScore: 5, RiskSignals: `["sensitive_path"]`},
		{Timestamp: now, Method: "POST", URL: "http://b.com/2", Host: "b.com", Action: "BLOCK", RiskScore: 12, RiskSignals: `["sensitive_path","credential_pattern"]`},
		{Timestamp: now, Method: "GET", URL: "http://a.com/3", Host: "a.com", Action: "BAN", RiskScore: 25, RiskSignals: `["sensitive_path","credential_pattern","base64_payload"]`},
	}
	for _, e := range entries {
		if err := store.InsertAuditEntry(e); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.GetAuditStats(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if stats.TotalLastMinute != 3 {
		t.Errorf("total = %d, want 3", stats.TotalLastMinute)
	}
	if stats.ByAction["ALLOW"] != 1 {
		t.Errorf("ALLOW count = %d, want 1", stats.ByAction["ALLOW"])
	}
	if stats.ByAction["BLOCK"] != 1 {
		t.Errorf("BLOCK count = %d, want 1", stats.ByAction["BLOCK"])
	}
	if stats.ByAction["BAN"] != 1 {
		t.Errorf("BAN count = %d, want 1", stats.ByAction["BAN"])
	}
	if len(stats.TopHosts) == 0 {
		t.Fatal("expected top hosts")
	}
	if stats.TopHosts[0].Host != "a.com" {
		t.Errorf("top host = %q, want a.com", stats.TopHosts[0].Host)
	}
	if len(stats.RecentBans) != 1 {
		t.Fatalf("expected 1 ban, got %d", len(stats.RecentBans))
	}
	if len(stats.RuleHitFrequency) == 0 {
		t.Fatal("expected rule hit frequency data")
	}
	// sensitive_path should be most frequent (3 hits).
	if stats.RuleHitFrequency[0].RuleName != "sensitive_path" {
		t.Errorf("top rule = %q, want sensitive_path", stats.RuleHitFrequency[0].RuleName)
	}
	if stats.RuleHitFrequency[0].Count != 3 {
		t.Errorf("top rule count = %d, want 3", stats.RuleHitFrequency[0].Count)
	}
}

func TestParseSignals(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"valid array", `["a","b","c"]`, []string{"a", "b", "c"}},
		{"empty array", `[]`, []string{}},
		{"empty string", ``, nil},
		{"malformed JSON", `not json`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSignals(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSignals(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEmptyRiskSignalsStats(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// Insert entry with empty RiskSignals (should be normalized to "[]").
	entry := &AuditEntry{
		Timestamp:   time.Now(),
		Method:      "GET",
		URL:         "http://example.com",
		Host:        "example.com",
		Action:      "ALLOW",
		RiskSignals: "", // empty — would break json_each without normalization
	}
	if err := store.InsertAuditEntry(entry); err != nil {
		t.Fatalf("InsertAuditEntry: %v", err)
	}

	// GetAuditStats should not error (json_each on "[]" is fine).
	stats, err := store.GetAuditStats(time.Hour)
	if err != nil {
		t.Fatalf("GetAuditStats: %v", err)
	}
	if stats.TotalLastMinute != 1 {
		t.Errorf("total = %d, want 1", stats.TotalLastMinute)
	}
}

func TestOpenIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	store1.Close()

	// Second open on same path should succeed (migrations are idempotent).
	store2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	store2.Close()
}

func TestInsertAndListResponseScoringRules(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	rules := []ScoringRule{
		{Name: "resp_c", Expr: `status_code >= 500`, Points: 3, Enabled: true, Note: "server error"},
		{Name: "resp_a", Expr: `body_size > 1000`, Points: 5, Enabled: false, Note: ""},
		{Name: "resp_b", Expr: `host == "evil.com"`, Points: 10, Enabled: true, Note: "evil"},
	}
	if err := store.InsertResponseScoringRules(rules); err != nil {
		t.Fatalf("InsertResponseScoringRules: %v", err)
	}

	got, err := store.ListResponseScoringRules()
	if err != nil {
		t.Fatalf("ListResponseScoringRules: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(got))
	}
	// Ordered by name.
	if got[0].Name != "resp_a" {
		t.Errorf("first name = %q, want resp_a", got[0].Name)
	}
	if got[1].Name != "resp_b" {
		t.Errorf("second name = %q, want resp_b", got[1].Name)
	}
	if got[2].Name != "resp_c" {
		t.Errorf("third name = %q, want resp_c", got[2].Name)
	}
}

func TestCountResponseScoringRulesEmpty(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	count, err := store.CountResponseScoringRules()
	if err != nil {
		t.Fatalf("CountResponseScoringRules: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestInsertResponseScoringRuleSingle(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	r := &ScoringRule{Name: "resp_test", Expr: `status_code == 200`, Points: 2, Enabled: true, Note: "ok check"}
	if err := store.InsertResponseScoringRule(r); err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListResponseScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "resp_test" {
		t.Errorf("name = %q, want resp_test", rules[0].Name)
	}
	if rules[0].Points != 2 {
		t.Errorf("points = %d, want 2", rules[0].Points)
	}
	if !rules[0].Enabled {
		t.Error("expected enabled=true")
	}
	if rules[0].Note != "ok check" {
		t.Errorf("note = %q, want %q", rules[0].Note, "ok check")
	}
}

func TestUpdateResponseScoringRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.InsertResponseScoringRule(&ScoringRule{
		Name: "r1", Expr: "true", Points: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateResponseScoringRule("r1", "false", 10, false, "updated"); err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListResponseScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Expr != "false" {
		t.Errorf("expr = %q, want false", rules[0].Expr)
	}
	if rules[0].Points != 10 {
		t.Errorf("points = %d, want 10", rules[0].Points)
	}
	if rules[0].Enabled {
		t.Error("expected enabled=false")
	}
	if rules[0].Note != "updated" {
		t.Errorf("note = %q, want updated", rules[0].Note)
	}
}

func TestUpdateResponseScoringRuleNotFound(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.UpdateResponseScoringRule("nonexistent", "true", 1, true, ""); err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestDeleteResponseScoringRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.InsertResponseScoringRule(&ScoringRule{
		Name: "r1", Expr: "true", Points: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteResponseScoringRule("r1"); err != nil {
		t.Fatal(err)
	}

	count, err := store.CountResponseScoringRules()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}

	// Delete nonexistent should error.
	if err := store.DeleteResponseScoringRule("nonexistent"); err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestDeleteAuditEntriesBefore(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	now := time.Now()
	old := now.Add(-2 * time.Hour)
	recent := now.Add(-10 * time.Minute)

	entries := []*AuditEntry{
		{Timestamp: old, Method: "GET", URL: "http://a.com/1", Host: "a.com", Action: "ALLOW", RiskSignals: "[]"},
		{Timestamp: old, Method: "GET", URL: "http://a.com/2", Host: "a.com", Action: "ALLOW", RiskSignals: "[]"},
		{Timestamp: old, Method: "GET", URL: "http://a.com/3", Host: "a.com", Action: "ALLOW", RiskSignals: "[]"},
		{Timestamp: recent, Method: "GET", URL: "http://b.com/4", Host: "b.com", Action: "ALLOW", RiskSignals: "[]"},
		{Timestamp: recent, Method: "GET", URL: "http://b.com/5", Host: "b.com", Action: "ALLOW", RiskSignals: "[]"},
	}
	for _, e := range entries {
		if err := store.InsertAuditEntry(e); err != nil {
			t.Fatal(err)
		}
	}

	// Delete entries older than 1 hour.
	cutoff := now.Add(-1 * time.Hour)
	deleted, err := store.DeleteAuditEntriesBefore(cutoff, 100)
	if err != nil {
		t.Fatalf("DeleteAuditEntriesBefore: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	// Verify only recent entries remain.
	remaining, err := store.ListAuditEntries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2", len(remaining))
	}
}

func TestDeleteAuditEntriesBeforeBatching(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	old := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 25; i++ {
		e := &AuditEntry{
			Timestamp: old, Method: "GET", URL: "http://a.com",
			Host: "a.com", Action: "ALLOW", RiskSignals: "[]",
		}
		if err := store.InsertAuditEntry(e); err != nil {
			t.Fatal(err)
		}
	}

	// Delete with small batch size to exercise the loop.
	deleted, err := store.DeleteAuditEntriesBefore(time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 25 {
		t.Errorf("deleted = %d, want 25", deleted)
	}

	remaining, err := store.ListAuditEntries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %d, want 0", len(remaining))
	}
}

func TestDeleteAuditEntriesBeforeNoop(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// Nothing to delete on empty table.
	deleted, err := store.DeleteAuditEntriesBefore(time.Now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}

func TestIncrementalVacuum(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// Should not error even on an empty database.
	if err := store.IncrementalVacuum(); err != nil {
		t.Fatalf("IncrementalVacuum: %v", err)
	}
}
