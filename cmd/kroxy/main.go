package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/standard"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"

	"github.com/kroxy/kroxy/internal/alerts"
	"github.com/kroxy/kroxy/internal/api"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/bot"
	"github.com/kroxy/kroxy/internal/config"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/proxy"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/validation"
	"github.com/kroxy/kroxy/internal/version"
	"github.com/kroxy/kroxy/internal/waf"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set admin addr for self-reference detection (prevent proxy loops)
	validation.SetAdminAddr(cfg.AdminAddr)
	// Wire AllowPrivateBackends config into validation package
	validation.SetAllowPrivateBackends(cfg.AllowPrivateBackends)

	// Initialize store
	db, err := store.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer db.Close()

	// Initialize audit logger
	auditLogPath := os.Getenv("KROXY_AUDIT_LOG")
	if auditLogPath == "" {
		auditLogPath = "/data/audit.log"
	}
	if err := audit.Init(auditLogPath); err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}

	// Initialize bot detection
	bot.InitGlobals(os.Getenv("KROXY_BOT_SECRET"))

	// Initialize access log store
	logStorePath := os.Getenv("KROXY_ACCESS_LOG")
	if logStorePath == "" {
		logStorePath = "/data/access.log"
	}
	logStore, err := proxy.NewLogStore(logStorePath)
	if err != nil {
		log.Printf("Warning: failed to initialize access log store: %v", err)
	} else {
		proxy.SetGlobalLogStore(logStore)
	}

	// Initialize alert manager
	alertManager := alerts.NewManager()
	alerts.SetGlobalManager(alertManager)

	// Load webhooks from database
	webhooks, err := db.GetWebhooks()
	if err != nil {
		log.Printf("Warning: failed to load webhooks: %v", err)
	} else {
		alertWebhooks := make([]alerts.Webhook, len(webhooks))
		for i, w := range webhooks {
			alertWebhooks[i] = alerts.Webhook{
				ID:        w.ID,
				Name:      w.Name,
				URL:       w.URL,
				Events:    w.Events,
				Enabled:   w.Enabled,
				Secret:    w.Secret,
				CreatedAt: w.CreatedAt,
			}
		}
		alertManager.UpdateWebhooks(alertWebhooks)
		log.Printf("Loaded %d webhook(s)", len(alertWebhooks))
	}

	// Initialize proxy
	px, err := proxy.New(db, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	// Create cert directory for manual TLS certificates
	if cfg.TLSEnabled {
		certDir := "/data/certs"
		if err := os.MkdirAll(certDir, 0700); err != nil {
			log.Printf("Warning: failed to create cert directory %s: %v", certDir, err)
		}
		// Create Caddy ACME storage directory
		acmeDir := "/home/kroxy/.local/share/caddy"
		if err := os.MkdirAll(acmeDir, 0700); err != nil {
			log.Printf("Warning: failed to create ACME directory %s: %v", acmeDir, err)
		}
	}

	// Start proxy
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := px.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	// Start API server
	apiServer := api.New(db)
	apiServer.SetProxyReloadFunc(func() error {
		return px.Reload()
	})
	apiServer.SetWAFReloadFunc(func() error {
		// Rebuild global WAF engine
		signingKey, _ := crypto.GetWAFSigningKey()

		globalWAF, err := waf.New(db, waf.Config{
			Enabled:    true,
			Mode:       "block",
			Ruleset:    "owasp-crs",
			SigningKey: signingKey,
		}, audit.GetLogger(), nil, "block")
		if err != nil {
			return err
		}
		proxy.SetGlobalWAF(globalWAF)

		// Rebuild per-route WAF engines, respecting each route's WAF mode
		routes, routeErr := db.GetRoutes()
		if routeErr != nil {
			return fmt.Errorf("failed to get routes for WAF reload: %w", routeErr)
		}
		routeMap := make(map[int]store.Route)
		for _, rt := range routes {
			routeMap[rt.ID] = rt
		}

		for _, routeID := range proxy.GetAllRouteWAFIDs() {
			routeMode := "block"
			if rt, ok := routeMap[routeID]; ok && rt.WAFMode != "" {
				routeMode = rt.WAFMode
			}
			routeWAF, err := waf.New(db, waf.Config{
				Enabled:    true,
				Mode:       routeMode,
				Ruleset:    "owasp-crs",
				SigningKey: signingKey,
			}, audit.GetLogger(), &routeID, routeMode)
			if err != nil {
				log.Printf("Warning: failed to rebuild WAF for route %d: %v", routeID, err)
				continue
			}
			proxy.SetRouteWAF(routeID, routeWAF)
		}
		return nil
	})
	apiServer.RegisterPageRoutes() // Register frontend page routes
	server := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           apiServer,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB max headers
	}

	go func() {
		log.Printf("API server listening on %s", cfg.AdminAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	log.Printf("Kroxy v%s started - Proxy: %s, API: %s", version.Version, cfg.ProxyAddr, cfg.AdminAddr)

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	px.Stop()
	server.Shutdown(ctx)
	if logStore != nil {
		logStore.Close()
	}
}
