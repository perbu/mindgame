package scoring

import (
	"strings"
	"testing"

	"github.com/perbu/mindgame/internal/db"
)

func TestNewRejectsNonBoolExpr(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "int_return", Expr: `body_size + 10`, Points: 1, Enabled: true},
	}
	_, err := New(rules)
	if err == nil {
		t.Fatal("expected error for non-bool CEL expression")
	}
	if !strings.Contains(err.Error(), "must return bool") {
		t.Errorf("error = %q, want 'must return bool'", err)
	}
}

func TestValidateRequestExpr(t *testing.T) {
	// Valid bool expression.
	if err := ValidateRequestExpr(`method == "GET"`); err != nil {
		t.Errorf("valid expr failed: %v", err)
	}

	// Invalid syntax.
	if err := ValidateRequestExpr(`this is not valid!!!`); err == nil {
		t.Error("expected error for invalid syntax")
	}

	// Non-bool return.
	err := ValidateRequestExpr(`body_size + 10`)
	if err == nil {
		t.Error("expected error for non-bool return")
	}
	if err != nil && !strings.Contains(err.Error(), "must return bool") {
		t.Errorf("error = %q, want 'must return bool'", err)
	}
}

func TestNewInvalidExpr(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "bad", Expr: `this is not valid CEL !!!`, Points: 1, Enabled: true},
	}
	_, err := New(rules)
	if err == nil {
		t.Fatal("expected error for invalid CEL expression")
	}
}

func TestNewSkipsDisabled(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "disabled", Expr: `true`, Points: 10, Enabled: false},
		{Name: "enabled", Expr: `true`, Points: 5, Enabled: true},
	}
	eng, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, want 1", eng.RuleCount())
	}
}

func TestEvalNoRules(t *testing.T) {
	eng, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result := eng.Eval(RequestVars{})
	if result.Score != 0 {
		t.Errorf("Score = %d, want 0", result.Score)
	}
	if result.Signals != nil {
		t.Errorf("Signals = %v, want nil", result.Signals)
	}
}

func TestEvalSingleMatch(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "get_check", Expr: `method == "GET"`, Points: 5, Enabled: true},
	}
	eng, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result := eng.Eval(RequestVars{Method: "GET"})
	if result.Score != 5 {
		t.Errorf("Score = %d, want 5", result.Score)
	}
	if len(result.Signals) != 1 || result.Signals[0] != "get_check" {
		t.Errorf("Signals = %v, want [get_check]", result.Signals)
	}
}

func TestEvalMultipleRules(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "r1", Expr: `method == "POST"`, Points: 3, Enabled: true},
		{Name: "r2", Expr: `body_size > 100`, Points: 5, Enabled: true},
		{Name: "r3", Expr: `host == "evil.com"`, Points: 10, Enabled: true},
	}
	eng, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result := eng.Eval(RequestVars{
		Method:   "POST",
		BodySize: 200,
		Host:     "safe.com",
		Headers:  map[string]string{},
	})
	// r1 matches (POST), r2 matches (200 > 100), r3 doesn't (safe.com != evil.com)
	if result.Score != 8 {
		t.Errorf("Score = %d, want 8", result.Score)
	}
	if len(result.Signals) != 2 {
		t.Errorf("Signals count = %d, want 2", len(result.Signals))
	}
}

func TestEvalNoMatch(t *testing.T) {
	rules := []db.ScoringRule{
		{Name: "r1", Expr: `method == "DELETE"`, Points: 10, Enabled: true},
	}
	eng, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result := eng.Eval(RequestVars{Method: "GET", Headers: map[string]string{}})
	if result.Score != 0 {
		t.Errorf("Score = %d, want 0", result.Score)
	}
	if len(result.Signals) != 0 {
		t.Errorf("Signals = %v, want empty", result.Signals)
	}
}

func TestSignalsJSON(t *testing.T) {
	r := Result{}
	if got := r.SignalsJSON(); got != "[]" {
		t.Errorf("empty SignalsJSON = %q, want %q", got, "[]")
	}

	r = Result{Score: 5, Signals: []string{"r1", "r2"}}
	got := r.SignalsJSON()
	if got != `["r1","r2"]` {
		t.Errorf("SignalsJSON = %q, want %q", got, `["r1","r2"]`)
	}
}

// --- Default rule tests ---

func defaultEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := New(DefaultRules())
	if err != nil {
		t.Fatalf("New(DefaultRules): %v", err)
	}
	return eng
}

func TestDefaultRuleSensitivePath(t *testing.T) {
	eng := defaultEngine(t)
	for _, path := range []string{"/.env", "/.git/config", "/etc/passwd", "/admin", "/wp-admin"} {
		result := eng.Eval(RequestVars{
			Method:  "GET",
			Path:    path,
			Headers: map[string]string{},
		})
		if result.Score < 5 {
			t.Errorf("path %q: Score = %d, want >= 5", path, result.Score)
		}
		found := false
		for _, s := range result.Signals {
			if s == "sensitive_path" {
				found = true
			}
		}
		if !found {
			t.Errorf("path %q: expected sensitive_path signal, got %v", path, result.Signals)
		}
	}
}

func TestDefaultRuleLargeOutbound(t *testing.T) {
	eng := defaultEngine(t)
	result := eng.Eval(RequestVars{
		Method:   "POST",
		BodySize: 70000,
		Body:     strings.Repeat("x", 70000),
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "large_outbound" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected large_outbound signal, got %v", result.Signals)
	}
}

func TestDefaultRuleBase64Payload(t *testing.T) {
	eng := defaultEngine(t)
	b64 := strings.Repeat("ABCD", 100) // 400 chars of base64-like
	result := eng.Eval(RequestVars{
		Method:   "POST",
		Body:     b64,
		BodySize: len(b64),
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "base64_payload" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected base64_payload signal, got %v", result.Signals)
	}
}

func TestDefaultRuleConfidentialKeywords(t *testing.T) {
	eng := defaultEngine(t)
	result := eng.Eval(RequestVars{
		Method:   "POST",
		Body:     "this is a confidential document with password info",
		BodySize: 50,
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "confidential_keywords" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected confidential_keywords signal, got %v", result.Signals)
	}
}

func TestDefaultRuleCredentialPattern(t *testing.T) {
	eng := defaultEngine(t)
	result := eng.Eval(RequestVars{
		Method:   "POST",
		Body:     `{"token":"bearer eyJhbGciOiJIUzI1NiJ9","key":"sk-proj12345","aws":"AKIAIOSFODNN7EXAMPLE"}`,
		BodySize: 90,
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "credential_pattern" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected credential_pattern signal, got %v", result.Signals)
	}
}

func TestDefaultRuleDataURI(t *testing.T) {
	eng := defaultEngine(t)
	result := eng.Eval(RequestVars{
		Method:   "POST",
		Body:     `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA`,
		BodySize: 50,
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "data_uri" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected data_uri signal, got %v", result.Signals)
	}
}

func TestDefaultRuleBodyOnGet(t *testing.T) {
	eng := defaultEngine(t)
	result := eng.Eval(RequestVars{
		Method:   "GET",
		Body:     strings.Repeat("x", 2000),
		BodySize: 2000,
		Headers:  map[string]string{},
	})
	found := false
	for _, s := range result.Signals {
		if s == "body_on_get" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected body_on_get signal, got %v", result.Signals)
	}
}

func TestCumulativeScoreAboveBanThreshold(t *testing.T) {
	eng := defaultEngine(t)
	// Craft a request that triggers multiple rules to get >= 20 points.
	// sensitive_path (5) + confidential_keywords (5) + credential_pattern (8) + base64_payload (5) = 23
	body := `bearer eyJtoken123 confidential password sk-proj1234 ` + strings.Repeat("ABCD", 100)
	result := eng.Eval(RequestVars{
		Method:   "POST",
		Path:     "/admin",
		Body:     body,
		BodySize: len(body),
		Headers:  map[string]string{},
	})
	if result.Score < 20 {
		t.Errorf("Score = %d, want >= 20 (signals: %v)", result.Score, result.Signals)
	}
}
