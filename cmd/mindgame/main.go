package main

import (
	"context"
	_ "embed"
	"flag"
	"log"
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
	log.Printf("mindgame %s", strings.TrimSpace(version))
	defaults := proxy.DefaultBodyLimits()
	addr := flag.String("addr", ":8080", "listen address")
	uiAddr := flag.String("ui-addr", ":9090", "UI dashboard listen address")
	dbPath := flag.String("db", "audit.db", "path to SQLite database")
	caDir := flag.String("ca-dir", ".", "directory for CA certificate and key")
	seedPath := flag.String("seed", "", "path to seed file with domain rules")
	maxTextLog := flag.Int("max-text-log", defaults.MaxTextLog, "max bytes to log for text bodies")
	maxBinaryLog := flag.Int("max-binary-log", defaults.MaxBinaryLog, "max bytes to log for binary bodies")
	flag.Parse()

	limits := proxy.BodyLimits{
		MaxTextLog:   *maxTextLog,
		MaxBinaryLog: *maxBinaryLog,
	}

	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	certPath := filepath.Join(*caDir, "ca.pem")
	keyPath := filepath.Join(*caDir, "ca.key")
	authority, err := ca.New(certPath, keyPath)
	if err != nil {
		log.Fatalf("failed to initialize CA: %v", err)
	}
	log.Printf("CA cert: %s, key: %s", certPath, keyPath)

	if *seedPath != "" {
		rules, err := policy.ParseSeedFile(*seedPath)
		if err != nil {
			log.Fatalf("failed to parse seed file: %v", err)
		}
		if err := store.InsertDomainRules(rules); err != nil {
			log.Fatalf("failed to insert seed rules: %v", err)
		}
		log.Printf("loaded %d domain rules from %s", len(rules), *seedPath)
	}

	pol, err := policy.NewCache(store, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to create policy cache: %v", err)
	}
	defer pol.Stop()

	count, err := store.CountScoringRules()
	if err != nil {
		log.Fatalf("failed to count scoring rules: %v", err)
	}
	if count == 0 {
		if err := store.InsertScoringRules(scoring.DefaultRules()); err != nil {
			log.Fatalf("failed to seed scoring rules: %v", err)
		}
		log.Printf("seeded %d default scoring rules", len(scoring.DefaultRules()))
	}

	rules, err := store.ListScoringRules()
	if err != nil {
		log.Fatalf("failed to list scoring rules: %v", err)
	}
	scorer, err := scoring.New(rules)
	if err != nil {
		log.Fatalf("failed to create scoring engine: %v", err)
	}
	log.Printf("scoring engine loaded with %d rules", scorer.RuleCount())

	handler := proxy.New(store, authority, pol, scorer, limits)

	// SSE broker connects proxy audit writes to the UI live feed.
	broker := ui.NewBroker()
	handler.SetNotifier(broker)

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

	uiServer := ui.NewServer(store, pol, reloadScorer, broker)

	proxySrv := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}
	uiSrv := &http.Server{
		Addr:    *uiAddr,
		Handler: uiServer,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("proxy listening on %s", *addr)
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy listen error: %v", err)
		}
	}()

	go func() {
		log.Printf("UI dashboard listening on %s", *uiAddr)
		if err := uiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("UI listen error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("proxy shutdown error: %v", err)
	}
	if err := uiSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("UI shutdown error: %v", err)
	}
}
