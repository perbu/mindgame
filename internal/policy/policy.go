package policy

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/perbu/mindgame/internal/db"
)

// Tier classifies a domain's policy level.
type Tier string

const (
	TierAllow   Tier = "allow"
	TierDeny    Tier = "deny"
	TierDefault Tier = "" // unlisted — requires X-Reason
)

// Decision is the result of evaluating a host against the policy cache.
type Decision struct {
	Tier          Tier
	RequireReason bool
}

// Cache holds an in-memory map of domain rules and reloads periodically from the DB.
type Cache struct {
	store     *db.Store
	mu        sync.RWMutex
	rules     map[string]Tier // exact host → tier
	wildcards map[string]Tier // suffix → tier (e.g. ".slack.com" for "*.slack.com")
	stopCh    chan struct{}
	stopOnce  sync.Once
	interval  time.Duration
}

// NewCache creates a Cache, performs an initial load from the DB, and starts
// a background goroutine that reloads every interval.
func NewCache(store *db.Store, interval time.Duration) (*Cache, error) {
	c := &Cache{
		store:     store,
		rules:     make(map[string]Tier),
		wildcards: make(map[string]Tier),
		stopCh:    make(chan struct{}),
		interval:  interval,
	}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	go c.loop()
	return c, nil
}

func (c *Cache) loop() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.Reload(); err != nil {
				// Log but don't crash; keep serving stale data.
				slog.Error("policy reload error", "error", err)
			}
		case <-c.stopCh:
			return
		}
	}
}

// Reload fetches all domain rules from the DB and swaps the in-memory map.
func (c *Cache) Reload() error {
	rows, err := c.store.ListDomainRules()
	if err != nil {
		return err
	}
	exact := make(map[string]Tier, len(rows))
	wild := make(map[string]Tier)
	for _, r := range rows {
		host := strings.ToLower(strings.TrimSpace(r.Host))
		if strings.HasPrefix(host, "*.") {
			// Store suffix keyed without the "*", e.g. ".slack.com".
			wild[host[1:]] = Tier(r.Tier)
		} else {
			exact[host] = Tier(r.Tier)
		}
	}
	c.mu.Lock()
	c.rules = exact
	c.wildcards = wild
	c.mu.Unlock()
	slog.Debug("policy cache reloaded", "exact", len(exact), "wildcards", len(wild))
	return nil
}

// Stop stops the background reload goroutine. Safe to call multiple times.
func (c *Cache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// Evaluate returns the policy decision for the given host.
// Exact rules take priority over wildcard rules.
func (c *Cache) Evaluate(host string) Decision {
	h := strings.ToLower(host)

	c.mu.RLock()
	tier, ok := c.rules[h]
	if !ok {
		// Walk parent suffixes: for "api.slack.com" try ".slack.com", then ".com".
		for i := 0; i < len(h); i++ {
			if h[i] == '.' {
				if t, wok := c.wildcards[h[i:]]; wok {
					tier = t
					ok = true
					break
				}
			}
		}
	}
	c.mu.RUnlock()

	if !ok {
		slog.Debug("policy evaluated", "host", host, "tier", "default")
		return Decision{Tier: TierDefault, RequireReason: true}
	}
	slog.Debug("policy evaluated", "host", host, "tier", string(tier))
	switch tier {
	case TierDeny:
		return Decision{Tier: TierDeny, RequireReason: false}
	case TierAllow:
		return Decision{Tier: TierAllow, RequireReason: false}
	default:
		return Decision{Tier: TierDefault, RequireReason: true}
	}
}

// ValidateHost checks that host is a valid domain or wildcard pattern.
// Accepted forms: "example.com" or "*.example.com".
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	// Strip optional wildcard prefix for suffix validation.
	suffix := host
	if strings.HasPrefix(host, "*.") {
		suffix = host[2:]
	}
	if suffix == "" {
		return fmt.Errorf("wildcard must have a domain suffix (e.g. *.example.com)")
	}
	if strings.Contains(suffix, "*") {
		return fmt.Errorf("only a leading *. wildcard is allowed")
	}
	if strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") {
		return fmt.Errorf("domain must not start or end with a dot")
	}
	if strings.Contains(suffix, "..") {
		return fmt.Errorf("domain must not contain consecutive dots")
	}
	return nil
}

// ParseSeedFile reads a seed file and returns domain rules.
// Format: <tier> <host> [# optional note]
// Lines starting with # and blank lines are ignored.
func ParseSeedFile(path string) ([]db.DomainRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []db.DomainRule
	scanner := bufio.NewScanner(f)
	lineNum := 0
	now := time.Now()

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split off inline comment.
		var note string
		if idx := strings.Index(line, "#"); idx >= 0 {
			note = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected '<tier> <host>', got %q", lineNum, line)
		}

		tier := fields[0]
		host := fields[1]

		if tier != "allow" && tier != "deny" {
			return nil, fmt.Errorf("line %d: invalid tier %q (must be 'allow' or 'deny')", lineNum, tier)
		}
		if err := ValidateHost(host); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		rules = append(rules, db.DomainRule{
			Host:      strings.ToLower(host),
			Tier:      tier,
			CreatedAt: now,
			Note:      note,
		})
	}
	return rules, scanner.Err()
}
