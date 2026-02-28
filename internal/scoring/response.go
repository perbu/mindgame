package scoring

import (
	"log/slog"

	"github.com/google/cel-go/cel"
	"github.com/perbu/mindgame/internal/db"
)

// ResponseVars holds the variables available to response-phase CEL expressions.
type ResponseVars struct {
	Host        string
	URL         string
	StatusCode  int
	Body        string
	BodySize    int
	ContentType string
	Headers     map[string]string
}

// NewResponse compiles response scoring rules into a CEL engine.
func NewResponse(rules []db.ScoringRule) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("host", cel.StringType),
		cel.Variable("url", cel.StringType),
		cel.Variable("status_code", cel.IntType),
		cel.Variable("body", cel.StringType),
		cel.Variable("body_size", cel.IntType),
		cel.Variable("content_type", cel.StringType),
		cel.Variable("headers", cel.MapType(cel.StringType, cel.StringType)),
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

	slog.Debug("response scoring engine compiled", "rules", len(compiled))
	return &Engine{rules: compiled}, nil
}

// EvalResponse evaluates all compiled rules against the given response variables.
func (e *Engine) EvalResponse(vars ResponseVars) Result {
	if len(e.rules) == 0 {
		return Result{}
	}

	activation := map[string]any{
		"host":         vars.Host,
		"url":          vars.URL,
		"status_code":  int64(vars.StatusCode),
		"body":         vars.Body,
		"body_size":    int64(vars.BodySize),
		"content_type": vars.ContentType,
		"headers":      vars.Headers,
	}

	var result Result
	for _, r := range e.rules {
		out, _, err := r.prog.Eval(activation)
		if err != nil {
			slog.Warn("response scoring rule eval error", "rule", r.name, "error", err)
			continue
		}
		if out.Value() == true {
			slog.Debug("response scoring rule matched", "rule", r.name, "points", r.points)
			result.Score += r.points
			result.Signals = append(result.Signals, r.name)
		}
	}
	return result
}

// DefaultResponseRules returns the built-in response-phase scoring rules.
func DefaultResponseRules() []db.ScoringRule {
	return []db.ScoringRule{
		{
			Name:    "resp_prompt_injection",
			Expr:    `body.matches("(?i)(ignore previous instructions|ignore all prior|disregard (your|all|prior) instructions|forget (your|all) instructions)")`,
			Points:  10,
			Enabled: true,
			Note:    "Response contains prompt injection patterns",
		},
		{
			Name:    "resp_identity_override",
			Expr:    `body.matches("(?i)(you are now|from now on you|act as|pretend to be|you must believe)")`,
			Points:  8,
			Enabled: true,
			Note:    "Response attempts to override agent identity",
		},
		{
			Name:    "resp_instruction_injection",
			Expr:    `body.matches("(?i)(\\[system\\]|<system>|<<SYS>>|\\[INST\\]|<\\|im_start\\|>system)")`,
			Points:  10,
			Enabled: true,
			Note:    "Response contains system prompt markers",
		},
		{
			Name:    "resp_hidden_text",
			Expr:    `body.matches("(?i)(display:\\s*none|visibility:\\s*hidden|font-size:\\s*0|color:\\s*transparent)") || body.matches("<!--.{500,}-->")`,
			Points:  5,
			Enabled: true,
			Note:    "Response contains hidden text via CSS or oversized HTML comments",
		},
		{
			Name:    "resp_large_encoded_payload",
			Expr:    `body_size > 10000 && body.matches("[A-Za-z0-9+/=]{500,}")`,
			Points:  5,
			Enabled: true,
			Note:    "Large response with long base64-encoded payload",
		},
		{
			Name:    "resp_behavioral_override",
			Expr:    `body.matches("(?i)(do not tell|do not reveal|do not mention|keep this secret|never disclose|hide this from)")`,
			Points:  8,
			Enabled: true,
			Note:    "Response attempts to impose secrecy on the agent",
		},
		{
			Name:    "resp_tool_abuse",
			Expr:    `body.matches("(?i)(execute this command|run this code|<script[^>]*>)") || body.matches("(?i)(eval\\(|exec\\(|system\\()")`,
			Points:  5,
			Enabled: true,
			Note:    "Response contains command execution or script injection patterns",
		},
	}
}
