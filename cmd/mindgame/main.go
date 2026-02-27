package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/perbu/mindgame/internal/ca"
	"github.com/perbu/mindgame/internal/db"
	"github.com/perbu/mindgame/internal/policy"
	"github.com/perbu/mindgame/internal/proxy"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "audit.db", "path to SQLite database")
	caDir := flag.String("ca-dir", ".", "directory for CA certificate and key")
	seedPath := flag.String("seed", "", "path to seed file with domain rules")
	flag.Parse()

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

	handler := proxy.New(store, authority, pol)

	srv := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("proxy listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
