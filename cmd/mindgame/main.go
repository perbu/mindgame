package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
	"github.com/perbu/mindgame/internal/proxy"
	"github.com/perbu/mindgame/internal/scoring"
	"github.com/perbu/mindgame/internal/ui"
)

//go:embed .version
var version string

func main() {
	defaults := proxy.DefaultBodyLimits()
	addr := flag.String("addr", ":8080", "listen address")
	uiAddr := flag.String("ui-addr", ":9090", "UI dashboard listen address")
	dbPath := flag.String("db", "audit.db", "path to SQLite database")
	caDir := flag.String("ca-dir", ".", "directory for CA certificate and key")
	seedPath := flag.String("seed", "", "path to seed file with domain rules")
	logLevelStr := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	maxTextLog := flag.Int("max-text-log", defaults.MaxTextLog, "max bytes to log for text bodies")
	maxBinaryLog := flag.Int("max-binary-log", defaults.MaxBinaryLog, "max bytes to log for binary bodies")
	flag.Parse()

	var logLevel slog.Level
	switch strings.ToLower(*logLevelStr) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "invalid log level %q, using info\n", *logLevelStr)
		logLevel = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	slog.Info("starting mindgame", "version", strings.TrimSpace(version))

	limits := proxy.BodyLimits{
		MaxTextLog:   *maxTextLog,
		MaxBinaryLog: *maxBinaryLog,
	}

	store, err := db.Open(*dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	slog.Debug("database opened", "path", *dbPath)

	certPath := filepath.Join(*caDir, "ca.pem")
	keyPath := filepath.Join(*caDir, "ca.key")
	authority, err := ca.New(certPath, keyPath)
	if err != nil {
		slog.Error("failed to initialize CA", "error", err)
		os.Exit(1)
	}
	slog.Info("CA initialized", "cert", certPath, "key", keyPath)

	if *seedPath != "" {
		rules, err := policy.ParseSeedFile(*seedPath)
		if err != nil {
			slog.Error("failed to parse seed file", "error", err)
			os.Exit(1)
		}
		if err := store.InsertDomainRules(rules); err != nil {
			slog.Error("failed to insert seed rules", "error", err)
			os.Exit(1)
		}
		slog.Info("loaded domain rules from seed file", "count", len(rules), "path", *seedPath)
	}

	pol, err := policy.NewCache(store, 30*time.Second)
	if err != nil {
		slog.Error("failed to create policy cache", "error", err)
		os.Exit(1)
	}
	defer pol.Stop()
	slog.Debug("policy cache created", "interval", 30*time.Second)

	count, err := store.CountScoringRules()
	if err != nil {
		slog.Error("failed to count scoring rules", "error", err)
		os.Exit(1)
	}
	if count == 0 {
		if err := store.InsertScoringRules(scoring.DefaultRules()); err != nil {
			slog.Error("failed to seed scoring rules", "error", err)
			os.Exit(1)
		}
		slog.Info("seeded default scoring rules", "count", len(scoring.DefaultRules()))
	}

	rules, err := store.ListScoringRules()
	if err != nil {
		slog.Error("failed to list scoring rules", "error", err)
		os.Exit(1)
	}
	scorer, err := scoring.New(rules)
	if err != nil {
		slog.Error("failed to create scoring engine", "error", err)
		os.Exit(1)
	}
	slog.Info("request scoring engine loaded", "rules", scorer.RuleCount())

	// Seed response scoring rules if empty.
	respCount, err := store.CountResponseScoringRules()
	if err != nil {
		slog.Error("failed to count response scoring rules", "error", err)
		os.Exit(1)
	}
	if respCount == 0 {
		if err := store.InsertResponseScoringRules(scoring.DefaultResponseRules()); err != nil {
			slog.Error("failed to seed response scoring rules", "error", err)
			os.Exit(1)
		}
		slog.Info("seeded default response scoring rules", "count", len(scoring.DefaultResponseRules()))
	}

	respRules, err := store.ListResponseScoringRules()
	if err != nil {
		slog.Error("failed to list response scoring rules", "error", err)
		os.Exit(1)
	}
	respScorer, err := scoring.NewResponse(respRules)
	if err != nil {
		slog.Error("failed to create response scoring engine", "error", err)
		os.Exit(1)
	}
	slog.Info("response scoring engine loaded", "rules", respScorer.RuleCount())

	handler := proxy.New(store, authority, pol, scorer, respScorer, limits)
	slog.Debug("proxy handler created")

	// SSE broker connects proxy audit writes to the UI live feed.
	broker := ui.NewBroker()
	handler.SetNotifier(broker)
	slog.Debug("SSE broker initialized")

	// reloadScorer compiles scoring rules from DB and hot-swaps the proxy's engine.
	reloadScorer := func() error {
		rules, err := store.ListScoringRules()
		if err != nil {
			return err
		}
		newScorer, err := scoring.New(rules)
		if err != nil {
			return err
		}
		handler.SetScorer(newScorer)
		return nil
	}

	// reloadRespScorer compiles response scoring rules from DB and hot-swaps the engine.
	reloadRespScorer := func() error {
		rules, err := store.ListResponseScoringRules()
		if err != nil {
			return err
		}
		newScorer, err := scoring.NewResponse(rules)
		if err != nil {
			return err
		}
		handler.SetResponseScorer(newScorer)
		return nil
	}

	uiServer := ui.NewServer(store, pol, reloadScorer, reloadRespScorer, broker)

	proxySrv := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}
	uiSrv := &http.Server{
		Addr:    *uiAddr,
		Handler: uiServer,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	slog.Debug("signal handler registered")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("proxy listening", "addr", *addr)
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy listen error", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		slog.Info("UI dashboard listening", "addr", *uiAddr)
		if err := uiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("UI listen error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	// Close broker first so SSE handlers exit and connections drain.
	broker.Close()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("proxy shutdown error", "error", err)
	}
	if err := uiSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("UI shutdown error", "error", err)
	}
}
