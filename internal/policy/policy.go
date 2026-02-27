package policy

import (
	"bufio"
	"fmt"
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
	store    *db.Store
	mu       sync.RWMutex
	rules    map[string]Tier
	stopCh   chan struct{}
	interval time.Duration
}

// NewCache creates a Cache, performs an initial load from the DB, and starts
// a background goroutine that reloads every interval.
func NewCache(store *db.Store, interval time.Duration) (*Cache, error) {
	c := &Cache{
		store:    store,
		rules:    make(map[string]Tier),
		stopCh:   make(chan struct{}),
		interval: interval,
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
				fmt.Fprintf(os.Stderr, "policy reload error: %v\n", err)
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
	m := make(map[string]Tier, len(rows))
	for _, r := range rows {
		m[strings.ToLower(r.Host)] = Tier(r.Tier)
	}
	c.mu.Lock()
	c.rules = m
	c.mu.Unlock()
	return nil
}

// Stop stops the background reload goroutine.
func (c *Cache) Stop() {
	close(c.stopCh)
}

// Evaluate returns the policy decision for the given host.
func (c *Cache) Evaluate(host string) Decision {
	c.mu.RLock()
	tier, ok := c.rules[strings.ToLower(host)]
	c.mu.RUnlock()

	if !ok {
		return Decision{Tier: TierDefault, RequireReason: true}
	}
	switch tier {
	case TierDeny:
		return Decision{Tier: TierDeny, RequireReason: false}
	case TierAllow:
		return Decision{Tier: TierAllow, RequireReason: false}
	default:
		return Decision{Tier: TierDefault, RequireReason: true}
	}
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

		rules = append(rules, db.DomainRule{
			Host:      strings.ToLower(host),
			Tier:      tier,
			CreatedAt: now,
			Note:      note,
		})
	}
	return rules, scanner.Err()
}
