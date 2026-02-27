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
