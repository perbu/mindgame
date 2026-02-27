package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// AuditEntry represents a single row in the audit_log table.
type AuditEntry struct {
	ID          int64
	Timestamp   time.Time
	Method      string
	URL         string
	Host        string
	Reason      string
	ReqHeaders  string
	ReqBody     string
	RespStatus  int
	RespBody    string
	RiskScore   int
	RiskSignals string
	Action      string
}

// Store wraps a SQLite database connection.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp    DATETIME NOT NULL,
	method       TEXT NOT NULL,
	url          TEXT NOT NULL,
	host         TEXT NOT NULL,
	reason       TEXT NOT NULL DEFAULT '',
	req_headers  TEXT NOT NULL DEFAULT '',
	req_body     TEXT NOT NULL DEFAULT '',
	resp_status  INTEGER NOT NULL DEFAULT 0,
	resp_body    TEXT NOT NULL DEFAULT '',
	risk_score   INTEGER NOT NULL DEFAULT 0,
	risk_signals TEXT NOT NULL DEFAULT '[]',
	action       TEXT NOT NULL DEFAULT 'ALLOW'
);

CREATE TABLE IF NOT EXISTS domain_rules (
	host       TEXT PRIMARY KEY,
	tier       TEXT NOT NULL CHECK (tier IN ('allow', 'deny')),
	banned     BOOLEAN NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	note       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scoring_rules (
	name    TEXT PRIMARY KEY,
	expr    TEXT NOT NULL,
	points  INTEGER NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	note    TEXT NOT NULL DEFAULT ''
);
`

// Open opens a SQLite database at path, enables WAL mode, and creates tables.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// InsertAuditEntry inserts an audit log entry and sets the ID on the entry.
func (s *Store) InsertAuditEntry(e *AuditEntry) error {
	res, err := s.db.Exec(`
		INSERT INTO audit_log (timestamp, method, url, host, reason, req_headers, req_body, resp_status, resp_body, risk_score, risk_signals, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Method, e.URL, e.Host, e.Reason, e.ReqHeaders, e.ReqBody,
		e.RespStatus, e.RespBody, e.RiskScore, e.RiskSignals, e.Action,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	e.ID = id
	return nil
}

// ListAuditEntries returns the most recent audit log entries, up to limit.
func (s *Store) ListAuditEntries(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, method, url, host, reason, req_headers, req_body, resp_status, resp_body, risk_score, risk_signals, action
		FROM audit_log
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Method, &e.URL, &e.Host, &e.Reason,
			&e.ReqHeaders, &e.ReqBody, &e.RespStatus, &e.RespBody,
			&e.RiskScore, &e.RiskSignals, &e.Action); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
