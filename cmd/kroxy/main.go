package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/kroxy/kroxy/internal/api"
	"github.com/kroxy/kroxy/internal/config"
	"github.com/kroxy/kroxy/internal/proxy"
	"github.com/kroxy/kroxy/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize store
	db, err := store.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer db.Close()

	// Initialize proxy
	px, err := proxy.New(db, cfg.ProxyAddr)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	// Start proxy
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := px.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	// Start API server
	apiServer := api.New(db)
	server := &http.Server{
		Addr:    cfg.AdminAddr,
		Handler: apiServer,
	}

	go func() {
		log.Printf("API server listening on %s", cfg.AdminAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	log.Printf("Kroxy started - Proxy: %s, API: %s", cfg.ProxyAddr, cfg.AdminAddr)

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	px.Stop()
	server.Shutdown(ctx)
}