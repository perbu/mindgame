package scoring

import (
	"encoding/json"
	"log"

	"github.com/google/cel-go/cel"
	"github.com/perbu/mindgame/internal/db"
)

// Result holds the cumulative score and list of triggered rule names.
type Result struct {
	Score   int
	Signals []string
}

// SignalsJSON returns the signals as a JSON array string. Returns "[]" if empty.
func (r Result) SignalsJSON() string {
	if len(r.Signals) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(r.Signals)
	return string(b)
}

// RequestVars holds the variables available to CEL expressions.
type RequestVars struct {
	Method       string
	URL          string
	Host         string
	Path         string
	Body         string
	BodySize     int
	BodyIsBinary bool
	Reason       string
	Headers      map[string]string
}

type compiledRule struct {
	name   string
	prog   cel.Program
	points int
}

// Engine evaluates requests against compiled CEL scoring rules.
type Engine struct {
	rules []compiledRule
}

// New compiles the enabled scoring rules into a CEL engine.
// Returns an error if any enabled rule has invalid CEL syntax.
func New(rules []db.ScoringRule) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("url", cel.StringType),
		cel.Variable("host", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("body", cel.StringType),
		cel.Variable("body_size", cel.IntType),
		cel.Variable("body_is_binary", cel.BoolType),
		cel.Variable("headers", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("reason", cel.StringType),
	)
	if err != nil {
		return nil, err
	}

	var compiled []compiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		ast, issues := env.Compile(r.Expr)
		if issues != nil && issues.Err() != nil {
			return nil, issues.Err()
		}
		prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledRule{
			name:   r.Name,
			prog:   prog,
			points: r.Points,
		})
	}

	return &Engine{rules: compiled}, nil
}

// Eval evaluates all compiled rules against the given request variables.
// Points from matching rules accumulate; eval errors on individual rules are
// logged and skipped.
func (e *Engine) Eval(vars RequestVars) Result {
	if len(e.rules) == 0 {
		return Result{}
	}

	activation := map[string]any{
		"method":         vars.Method,
		"url":            vars.URL,
		"host":           vars.Host,
		"path":           vars.Path,
		"body":           vars.Body,
		"body_size":      int64(vars.BodySize),
		"body_is_binary": vars.BodyIsBinary,
		"headers":        vars.Headers,
		"reason":         vars.Reason,
	}

	var result Result
	for _, r := range e.rules {
		out, _, err := r.prog.Eval(activation)
		if err != nil {
			log.Printf("scoring rule %q eval error: %v", r.name, err)
			continue
		}
		if out.Value() == true {
			result.Score += r.points
			result.Signals = append(result.Signals, r.name)
		}
	}
	return result
}

// RuleCount returns the number of compiled (enabled) rules.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// DefaultRules returns the built-in scoring rules.
func DefaultRules() []db.ScoringRule {
	return []db.ScoringRule{
		{
			Name:    "sensitive_path",
			Expr:    `path.matches("(?i)(/\\.env|/\\.git|/etc/passwd|/admin|/wp-admin)")`,
			Points:  5,
			Enabled: true,
			Note:    "Request targets a sensitive path",
		},
		{
			Name:    "large_outbound",
			Expr:    `method in ["POST", "PUT"] && body_size > 65536`,
			Points:  3,
			Enabled: true,
			Note:    "Large outbound POST/PUT payload",
		},
		{
			Name:    "base64_payload",
			Expr:    `body.matches("[A-Za-z0-9+/=]{200,}")`,
			Points:  5,
			Enabled: true,
			Note:    "Body contains long base64-like string",
		},
		{
			Name:    "confidential_keywords",
			Expr:    `body.matches("(?i)(confidential|internal|secret|private|password|api_key)")`,
			Points:  5,
			Enabled: true,
			Note:    "Body contains confidential keywords",
		},
		{
			Name:    "credential_pattern",
			Expr:    `body.matches("(?i)(bearer [a-z0-9_-]+|sk-[a-z0-9]+|AKIA[A-Z0-9])")`,
			Points:  8,
			Enabled: true,
			Note:    "Body contains credential patterns",
		},
		{
			Name:    "data_uri",
			Expr:    `body.matches("data:[a-z]+/[a-z]+;base64,")`,
			Points:  5,
			Enabled: true,
			Note:    "Body contains data URI with base64",
		},
		{
			Name:    "body_on_get",
			Expr:    `method == "GET" && body_size > 1024`,
			Points:  3,
			Enabled: true,
			Note:    "GET request with unexpectedly large body",
		},
	}
}
