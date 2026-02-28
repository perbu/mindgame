package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DomainRule represents a row in the domain_rules table.
type DomainRule struct {
	Host      string
	Tier      string // "allow" or "deny"
	Banned    bool
	CreatedAt time.Time
	Note      string
}

// AuditEntry represents a single row in the audit_log table.
type AuditEntry struct {
	ID              int64
	Timestamp       time.Time
	Method          string
	URL             string
	Host            string
	Reason          string
	ReqHeaders      string
	ReqBody         []byte
	ReqBodySize     int64
	RespStatus      int
	RespBody        []byte
	RespBodySize    int64
	RiskScore       int
	RiskSignals     string
	RespRiskScore   int
	RespRiskSignals string
	Action          string
}

// Store wraps a SQLite database connection.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp      DATETIME NOT NULL,
	method         TEXT NOT NULL,
	url            TEXT NOT NULL,
	host           TEXT NOT NULL,
	reason         TEXT NOT NULL DEFAULT '',
	req_headers    TEXT NOT NULL DEFAULT '',
	req_body       BLOB NOT NULL DEFAULT x'',
	req_body_size  INTEGER NOT NULL DEFAULT 0,
	resp_status    INTEGER NOT NULL DEFAULT 0,
	resp_body      BLOB NOT NULL DEFAULT x'',
	resp_body_size INTEGER NOT NULL DEFAULT 0,
	risk_score     INTEGER NOT NULL DEFAULT 0,
	risk_signals   TEXT NOT NULL DEFAULT '[]',
	action         TEXT NOT NULL DEFAULT 'ALLOW'
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

CREATE TABLE IF NOT EXISTS response_scoring_rules (
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
	if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Add columns for existing databases (ignore "duplicate column" errors).
	for _, stmt := range []string{
		`ALTER TABLE audit_log ADD COLUMN req_body_size INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_log ADD COLUMN resp_body_size INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_log ADD COLUMN resp_risk_score INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_log ADD COLUMN resp_risk_signals TEXT NOT NULL DEFAULT '[]'`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				db.Close()
				return nil, fmt.Errorf("db.Open: migrate: %w", err)
			}
		}
	}

	// Indexes for common query patterns (idempotent).
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_host ON audit_log(host)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("db.Open: create index: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// InsertAuditEntry inserts an audit log entry and sets the ID on the entry.
func (s *Store) InsertAuditEntry(e *AuditEntry) error {
	// Normalize nil slices to empty — SQLite NOT NULL rejects SQL NULL.
	reqBody := e.ReqBody
	if reqBody == nil {
		reqBody = []byte{}
	}
	respBody := e.RespBody
	if respBody == nil {
		respBody = []byte{}
	}
	riskSignals := e.RiskSignals
	if riskSignals == "" {
		riskSignals = "[]"
	}
	respRiskSignals := e.RespRiskSignals
	if respRiskSignals == "" {
		respRiskSignals = "[]"
	}
	res, err := s.db.Exec(`
		INSERT INTO audit_log (timestamp, method, url, host, reason, req_headers, req_body, req_body_size, resp_status, resp_body, resp_body_size, risk_score, risk_signals, resp_risk_score, resp_risk_signals, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Method, e.URL, e.Host, e.Reason, e.ReqHeaders, reqBody, e.ReqBodySize,
		e.RespStatus, respBody, e.RespBodySize, e.RiskScore, riskSignals, e.RespRiskScore, respRiskSignals, e.Action,
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
// Bodies are omitted to avoid loading large BLOBs; use GetAuditEntry for full detail.
func (s *Store) ListAuditEntries(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, method, url, host, reason, req_headers, req_body_size, resp_status, resp_body_size, risk_score, risk_signals, resp_risk_score, resp_risk_signals, action
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
			&e.ReqHeaders, &e.ReqBodySize, &e.RespStatus, &e.RespBodySize,
			&e.RiskScore, &e.RiskSignals, &e.RespRiskScore, &e.RespRiskSignals, &e.Action); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// LookupDomainRule returns the domain rule for the given host, or (nil, nil) if not found.
func (s *Store) LookupDomainRule(host string) (*DomainRule, error) {
	var r DomainRule
	err := s.db.QueryRow(`SELECT host, tier, banned, created_at, note FROM domain_rules WHERE host = ?`, host).
		Scan(&r.Host, &r.Tier, &r.Banned, &r.CreatedAt, &r.Note)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListDomainRules returns all domain rules ordered by host.
func (s *Store) ListDomainRules() ([]DomainRule, error) {
	rows, err := s.db.Query(`SELECT host, tier, banned, created_at, note FROM domain_rules ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule
	for rows.Next() {
		var r DomainRule
		if err := rows.Scan(&r.Host, &r.Tier, &r.Banned, &r.CreatedAt, &r.Note); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// InsertDomainRule upserts a single domain rule.
func (s *Store) InsertDomainRule(r *DomainRule) error {
	_, err := s.db.Exec(`
		INSERT INTO domain_rules (host, tier, banned, created_at, note)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET tier=excluded.tier, banned=excluded.banned, note=excluded.note`,
		r.Host, r.Tier, r.Banned, r.CreatedAt, r.Note,
	)
	return err
}

// ScoringRule represents a row in the scoring_rules table.
type ScoringRule struct {
	Name    string
	Expr    string
	Points  int
	Enabled bool
	Note    string
}

// ListScoringRules returns all scoring rules ordered by name.
func (s *Store) ListScoringRules() ([]ScoringRule, error) {
	rows, err := s.db.Query(`SELECT name, expr, points, enabled, note FROM scoring_rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ScoringRule
	for rows.Next() {
		var r ScoringRule
		if err := rows.Scan(&r.Name, &r.Expr, &r.Points, &r.Enabled, &r.Note); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CountScoringRules returns the number of rows in the scoring_rules table.
func (s *Store) CountScoringRules() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scoring_rules`).Scan(&count)
	return count, err
}

// InsertScoringRules batch-inserts scoring rules in a single transaction.
func (s *Store) InsertScoringRules(rules []ScoringRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO scoring_rules (name, expr, points, enabled, note) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rules {
		if _, err := stmt.Exec(r.Name, r.Expr, r.Points, r.Enabled, r.Note); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertDomainRules batch-upserts domain rules in a single transaction.
func (s *Store) InsertDomainRules(rules []DomainRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO domain_rules (host, tier, banned, created_at, note)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET tier=excluded.tier, banned=excluded.banned, note=excluded.note`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rules {
		if _, err := stmt.Exec(r.Host, r.Tier, r.Banned, r.CreatedAt, r.Note); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpdateDomainRule updates an existing domain rule.
func (s *Store) UpdateDomainRule(host, tier string, banned bool, note string) error {
	res, err := s.db.Exec(`UPDATE domain_rules SET tier=?, banned=?, note=? WHERE host=?`,
		tier, banned, note, host)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("domain rule %q not found", host)
	}
	return nil
}

// DeleteDomainRule deletes a domain rule by host.
func (s *Store) DeleteDomainRule(host string) error {
	res, err := s.db.Exec(`DELETE FROM domain_rules WHERE host=?`, host)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("domain rule %q not found", host)
	}
	return nil
}

// ListDomainRulesFiltered returns domain rules matching the host filter, with banned rules sorted to top.
func (s *Store) ListDomainRulesFiltered(hostFilter string) ([]DomainRule, error) {
	query := `SELECT host, tier, banned, created_at, note FROM domain_rules`
	var args []any
	if hostFilter != "" {
		query += ` WHERE host LIKE ?`
		args = append(args, "%"+hostFilter+"%")
	}
	query += ` ORDER BY banned DESC, host`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRule
	for rows.Next() {
		var r DomainRule
		if err := rows.Scan(&r.Host, &r.Tier, &r.Banned, &r.CreatedAt, &r.Note); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// InsertScoringRule inserts a single scoring rule.
func (s *Store) InsertScoringRule(r *ScoringRule) error {
	_, err := s.db.Exec(`INSERT INTO scoring_rules (name, expr, points, enabled, note) VALUES (?, ?, ?, ?, ?)`,
		r.Name, r.Expr, r.Points, r.Enabled, r.Note)
	return err
}

// UpdateScoringRule updates an existing scoring rule.
func (s *Store) UpdateScoringRule(name, expr string, points int, enabled bool, note string) error {
	res, err := s.db.Exec(`UPDATE scoring_rules SET expr=?, points=?, enabled=?, note=? WHERE name=?`,
		expr, points, enabled, note, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("scoring rule %q not found", name)
	}
	return nil
}

// DeleteScoringRule deletes a scoring rule by name.
func (s *Store) DeleteScoringRule(name string) error {
	res, err := s.db.Exec(`DELETE FROM scoring_rules WHERE name=?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("scoring rule %q not found", name)
	}
	return nil
}

// GetAuditEntry returns a single audit entry by ID, or (nil, nil) if not found.
func (s *Store) GetAuditEntry(id int64) (*AuditEntry, error) {
	var e AuditEntry
	err := s.db.QueryRow(`
		SELECT id, timestamp, method, url, host, reason, req_headers, req_body, req_body_size, resp_status, resp_body, resp_body_size, risk_score, risk_signals, resp_risk_score, resp_risk_signals, action
		FROM audit_log WHERE id = ?`, id).
		Scan(&e.ID, &e.Timestamp, &e.Method, &e.URL, &e.Host, &e.Reason,
			&e.ReqHeaders, &e.ReqBody, &e.ReqBodySize, &e.RespStatus, &e.RespBody, &e.RespBodySize,
			&e.RiskScore, &e.RiskSignals, &e.RespRiskScore, &e.RespRiskSignals, &e.Action)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// AuditFilter specifies criteria for filtering audit log entries.
type AuditFilter struct {
	Action   string
	Host     string
	MinScore int
	After    time.Time
	Before   time.Time
	Limit    int
	AfterID  int64
}

// ListAuditEntriesFiltered returns audit entries matching the given filter.
func (s *Store) ListAuditEntriesFiltered(f AuditFilter) ([]AuditEntry, error) {
	var clauses []string
	var args []any

	if f.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, f.Action)
	}
	if f.Host != "" {
		clauses = append(clauses, "host LIKE ?")
		args = append(args, "%"+f.Host+"%")
	}
	if f.MinScore > 0 {
		clauses = append(clauses, "risk_score >= ?")
		args = append(args, f.MinScore)
	}
	if !f.After.IsZero() {
		clauses = append(clauses, "timestamp > ?")
		args = append(args, f.After)
	}
	if !f.Before.IsZero() {
		clauses = append(clauses, "timestamp < ?")
		args = append(args, f.Before)
	}
	if f.AfterID > 0 {
		clauses = append(clauses, "id < ?")
		args = append(args, f.AfterID)
	}

	query := `SELECT id, timestamp, method, url, host, reason, req_headers, req_body_size, resp_status, resp_body_size, risk_score, risk_signals, resp_risk_score, resp_risk_signals, action FROM audit_log`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY id DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query += " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Method, &e.URL, &e.Host, &e.Reason,
			&e.ReqHeaders, &e.ReqBodySize, &e.RespStatus, &e.RespBodySize,
			&e.RiskScore, &e.RiskSignals, &e.RespRiskScore, &e.RespRiskSignals, &e.Action); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// HostCount holds a host and its request count.
type HostCount struct {
	Host  string
	Count int
}

// HostAvgScore holds a host, its average risk score, and request count.
type HostAvgScore struct {
	Host     string
	AvgScore float64
	Count    int
}

// RuleHitCount holds a rule name and how many times it was triggered.
type RuleHitCount struct {
	RuleName string
	Count    int
}

// AuditStats holds aggregated audit log statistics.
type AuditStats struct {
	TotalLastMinute  int
	ByAction         map[string]int
	TopHosts         []HostCount
	TopRiskHosts     []HostAvgScore
	RecentBans       []AuditEntry
	RuleHitFrequency []RuleHitCount
}

// GetAuditStats returns aggregated audit statistics for the given time window.
func (s *Store) GetAuditStats(window time.Duration) (*AuditStats, error) {
	cutoff := time.Now().Add(-window)
	stats := &AuditStats{
		ByAction: make(map[string]int),
	}

	// Total requests in window.
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE timestamp > ?`, cutoff).Scan(&stats.TotalLastMinute)
	if err != nil {
		return nil, err
	}

	// By action.
	rows, err := s.db.Query(`SELECT action, COUNT(*) FROM audit_log WHERE timestamp > ? GROUP BY action`, cutoff)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByAction[action] = count
	}
	rows.Close()

	// Top hosts by count.
	rows, err = s.db.Query(`SELECT host, COUNT(*) as cnt FROM audit_log WHERE timestamp > ? GROUP BY host ORDER BY cnt DESC LIMIT 10`, cutoff)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hc HostCount
		if err := rows.Scan(&hc.Host, &hc.Count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TopHosts = append(stats.TopHosts, hc)
	}
	rows.Close()

	// Top risk hosts by average score.
	rows, err = s.db.Query(`SELECT host, AVG(risk_score) as avg_score, COUNT(*) as cnt FROM audit_log WHERE timestamp > ? AND risk_score > 0 GROUP BY host ORDER BY avg_score DESC LIMIT 10`, cutoff)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ha HostAvgScore
		if err := rows.Scan(&ha.Host, &ha.AvgScore, &ha.Count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TopRiskHosts = append(stats.TopRiskHosts, ha)
	}
	rows.Close()

	// Recent bans.
	rows, err = s.db.Query(`
		SELECT id, timestamp, method, url, host, reason, req_headers, req_body, req_body_size, resp_status, resp_body, resp_body_size, risk_score, risk_signals, resp_risk_score, resp_risk_signals, action
		FROM audit_log WHERE timestamp > ? AND action IN ('BAN', 'RESP_BAN') ORDER BY id DESC LIMIT 10`, cutoff)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Method, &e.URL, &e.Host, &e.Reason,
			&e.ReqHeaders, &e.ReqBody, &e.ReqBodySize, &e.RespStatus, &e.RespBody, &e.RespBodySize,
			&e.RiskScore, &e.RiskSignals, &e.RespRiskScore, &e.RespRiskSignals, &e.Action); err != nil {
			rows.Close()
			return nil, err
		}
		stats.RecentBans = append(stats.RecentBans, e)
	}
	rows.Close()

	// Rule hit frequency using json_each.
	rows, err = s.db.Query(`
		SELECT j.value AS rule_name, COUNT(*) AS cnt
		FROM audit_log, json_each(audit_log.risk_signals) AS j
		WHERE audit_log.timestamp > ?
		GROUP BY j.value ORDER BY cnt DESC LIMIT 20`, cutoff)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rh RuleHitCount
		if err := rows.Scan(&rh.RuleName, &rh.Count); err != nil {
			rows.Close()
			return nil, err
		}
		// json_each returns JSON strings with quotes — strip them.
		rh.RuleName = strings.Trim(rh.RuleName, `"`)
		stats.RuleHitFrequency = append(stats.RuleHitFrequency, rh)
	}
	rows.Close()

	return stats, nil
}

// ParseSignals parses a JSON array of signal names from an audit entry's risk_signals field.
func ParseSignals(signalsJSON string) []string {
	var signals []string
	_ = json.Unmarshal([]byte(signalsJSON), &signals)
	return signals
}

// --- Response Scoring Rules ---

// ListResponseScoringRules returns all response scoring rules ordered by name.
func (s *Store) ListResponseScoringRules() ([]ScoringRule, error) {
	rows, err := s.db.Query(`SELECT name, expr, points, enabled, note FROM response_scoring_rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ScoringRule
	for rows.Next() {
		var r ScoringRule
		if err := rows.Scan(&r.Name, &r.Expr, &r.Points, &r.Enabled, &r.Note); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CountResponseScoringRules returns the number of rows in the response_scoring_rules table.
func (s *Store) CountResponseScoringRules() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM response_scoring_rules`).Scan(&count)
	return count, err
}

// InsertResponseScoringRule inserts a single response scoring rule.
func (s *Store) InsertResponseScoringRule(r *ScoringRule) error {
	_, err := s.db.Exec(`INSERT INTO response_scoring_rules (name, expr, points, enabled, note) VALUES (?, ?, ?, ?, ?)`,
		r.Name, r.Expr, r.Points, r.Enabled, r.Note)
	return err
}

// InsertResponseScoringRules batch-inserts response scoring rules in a single transaction.
func (s *Store) InsertResponseScoringRules(rules []ScoringRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO response_scoring_rules (name, expr, points, enabled, note) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rules {
		if _, err := stmt.Exec(r.Name, r.Expr, r.Points, r.Enabled, r.Note); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpdateResponseScoringRule updates an existing response scoring rule.
func (s *Store) UpdateResponseScoringRule(name, expr string, points int, enabled bool, note string) error {
	res, err := s.db.Exec(`UPDATE response_scoring_rules SET expr=?, points=?, enabled=?, note=? WHERE name=?`,
		expr, points, enabled, note, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("response scoring rule %q not found", name)
	}
	return nil
}

// DeleteResponseScoringRule deletes a response scoring rule by name.
func (s *Store) DeleteResponseScoringRule(name string) error {
	res, err := s.db.Exec(`DELETE FROM response_scoring_rules WHERE name=?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("response scoring rule %q not found", name)
	}
	return nil
}

// DeleteAuditEntriesBefore deletes audit entries older than the given time
// in batches to avoid holding long write locks. Returns total rows deleted.
func (s *Store) DeleteAuditEntriesBefore(t time.Time, batchSize int) (int64, error) {
	if batchSize <= 0 {
		batchSize = 10000
	}
	var total int64
	for {
		res, err := s.db.Exec(`DELETE FROM audit_log WHERE rowid IN (
			SELECT rowid FROM audit_log WHERE timestamp < ? LIMIT ?
		)`, t, batchSize)
		if err != nil {
			return total, fmt.Errorf("db.DeleteAuditEntriesBefore: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("db.DeleteAuditEntriesBefore: %w", err)
		}
		total += n
		if n < int64(batchSize) {
			break
		}
	}
	return total, nil
}

// IncrementalVacuum runs an incremental vacuum to reclaim free pages.
func (s *Store) IncrementalVacuum() error {
	_, err := s.db.Exec("PRAGMA incremental_vacuum")
	return err
}
