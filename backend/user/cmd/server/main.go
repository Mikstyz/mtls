package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	_ "github.com/lib/pq"
	"go.uber.org/automaxprocs/maxprocs"

	sharedconfig "mtls/shared/config"
	"mtls/user/internal/config"
	"mtls/user/internal/contentcleanup"
	"mtls/user/internal/httpapi"
	"mtls/user/internal/repositories"
	"mtls/user/internal/searchindex"
)

func main() {

	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.toml", "path to TOML configuration")
	flag.Parse()

	cfg, err := config.Load(*configPath)

	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	service := cfg.Services.User

	if err := sharedconfig.RequireMutualTLSForRemote(service.Auth.URL, service.TLS); err != nil {
		return fmt.Errorf("peer TLS configuration: %w", err)
	}

	serverTLS, requirePeerCert, err := service.TLS.ServerConfig()

	if err != nil {
		return fmt.Errorf("server TLS configuration: %w", err)
	}

	peerTransport, err := service.TLS.ClientTransport(service.Auth.URL)

	if err != nil {
		return fmt.Errorf("peer TLS configuration: %w", err)
	}

	if cfg.Resources.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.Resources.MaxProcs)
	} else if os.Getenv("GOMAXPROCS") == "" {
		if _, err := maxprocs.Set(); err != nil {
			log.Printf("automatic CPU configuration unavailable: %v", err)
		}
	}

	if cfg.Resources.MemoryLimitBytes > 0 {
		debug.SetMemoryLimit(cfg.Resources.MemoryLimitBytes)
	} else if os.Getenv("GOMEMLIMIT") == "" {
		_, err := memlimit.Set(
			memlimit.WithRatio(0.25),
			memlimit.WithProvider(memlimit.ApplyFallback(memlimit.FromCgroup, memlimit.FromSystem)),
		)

		if err != nil {
			log.Printf("automatic memory configuration unavailable: %v", err)
		}
	}

	if cfg.Database.Driver != "postgres" {
		return errors.New("database.driver must be postgres")
	}

	databaseUser, databasePassword, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, service.Database.User, service.Database.Password)

	if err != nil {
		return err
	}

	if service.Database.Name == "" {
		return errors.New("database name and user are required")
	}

	sslMode := cfg.Database.SSLMode

	if sslMode == "" {
		sslMode = "verify-full"
	}

	switch sslMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return errors.New("invalid database sslmode")
	}

	if err := sharedconfig.ValidateDatabaseTLS(service.Database.Host, sslMode); err != nil {
		return err
	}

	dbURL := &url.URL{Scheme: "postgres", User: url.UserPassword(databaseUser, databasePassword), Host: net.JoinHostPort(service.Database.Host, strconv.Itoa(cfg.Database.Port)), Path: "/" + service.Database.Name}
	query := dbURL.Query()
	query.Set("sslmode", sslMode)
	dbURL.RawQuery = query.Encode()
	db, err := sql.Open("postgres", dbURL.String())

	if err != nil {
		return errors.New("open database failed")
	}

	defer db.Close()

	maxOpen := cfg.Database.MaxOpenConns

	if maxOpen == 0 {
		maxOpen = 20
	}

	maxIdle := cfg.Database.MaxIdleConns

	if maxIdle == 0 {
		maxIdle = 5
	}

	if maxIdle > maxOpen {
		return errors.New("database.max_idle_conns must not exceed max_open_conns")
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return errors.New("connect to database failed")
	}

	const schemaCheck = `SELECT u.nickname, u.presence_visibility, d.deleted_at, d.presence_visibility, p.last_seen, r.nickname, l.operation, m.ready, m.revoked_at, m.media_kind, g.user_id, e.version, c.user_id
		FROM users u, deleted_users d, user_presence p, registration_provisions r,
			account_lifecycle_operations l, media_permissions m, media_permission_grants g, user_search_events e, content_purge_events c LIMIT 0`

	rows, err := db.QueryContext(ctx, schemaCheck)

	if err != nil {
		return fmt.Errorf("database schema is incomplete: %w", err)
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("check database schema: %w", err)
	}

	cookieName := "__Host-mtls_session"

	if !cfg.HTTP.CookieSecure {
		cookieName = "mtls_session"
	}

	repo := repositories.NewUserRepo(db)

	authToUser, userToAuth, err := sharedconfig.ResolveInternalSecrets(service.Auth.URL, cfg.Security.InternalSecret, cfg.Security.AuthToUserSecret, cfg.Security.UserToAuthSecret)

	if err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	if err := sharedconfig.ValidateInternalSecretRotation(authToUser, userToAuth, cfg.Security.PreviousAuthToUserSecret, cfg.Security.PreviousUserToAuthSecret); err != nil {
		return fmt.Errorf("internal service credential rotation: %w", err)
	}

	handler, err := httpapi.New(db, repo, service.Auth.URL, authToUser, cookieName, cfg.HTTP.AllowedOrigin)

	if err != nil {
		return fmt.Errorf("http configuration: %w", err)
	}

	handler.SetRecoveryMode(service.RecoveryMode)

	if service.RecoveryMode {
		log.Print("user recovery mode: requests and background processing are disabled")
	}

	if err := handler.SetAuthServiceSecret(userToAuth); err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	if err := handler.SetPreviousInternalSecret(cfg.Security.PreviousAuthToUserSecret); err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	var searchPublisher *searchindex.Publisher

	if service.Search.URL != "" {
		if service.Search.ReaderSecret == "" {
			service.Search.ReaderSecret = cfg.Services.Search.ReaderSecret
		}

		if service.Search.WriterSecret == "" {
			service.Search.WriterSecret = cfg.Services.Search.WriterSecret
		}
	}

	if service.Search.URL != "" || service.Search.ReaderSecret != "" || service.Search.WriterSecret != "" {
		if err := handler.SetSearchService(service.Search.URL, service.Search.ReaderSecret); err != nil {
			return fmt.Errorf("search service configuration: %w", err)
		}

		if service.Search.WriterSecret == service.Search.ReaderSecret {
			return errors.New("search credentials must be distinct")
		}

		for _, key := range []string{service.Search.ReaderSecret, service.Search.WriterSecret} {
			if key == authToUser || key == userToAuth || key == cfg.Security.PreviousAuthToUserSecret || key == cfg.Security.PreviousUserToAuthSecret {
				return errors.New("search credentials must be distinct from auth credentials")
			}
		}

		searchPublisher, err = searchindex.New(db, service.Search.URL, service.Search.WriterSecret)

		if err != nil {
			return fmt.Errorf("search publisher configuration: %w", err)
		}
	}

	if service.Content.SearchSecret != "" {
		for _, key := range []string{authToUser, userToAuth, cfg.Security.PreviousAuthToUserSecret, cfg.Security.PreviousUserToAuthSecret, service.Search.ReaderSecret, service.Search.WriterSecret, service.Content.PurgeSecret, cfg.Services.Content.PurgeSecret} {
			if key != "" && key == service.Content.SearchSecret {
				return errors.New("content search credential must be distinct")
			}
		}

		if err := handler.SetContentSearchService(service.Content.URL, service.Content.SearchSecret); err != nil {
			return fmt.Errorf("content search configuration: %w", err)
		}
	}

	var contentPublisher *contentcleanup.Publisher

	if service.Content.URL != "" && service.Content.PurgeSecret == "" {
		service.Content.PurgeSecret = cfg.Services.Content.PurgeSecret
	}

	if service.Content.PurgeSecret != "" || (service.Content.URL != "" && service.Content.SearchSecret == "") {
		for _, key := range []string{authToUser, userToAuth, cfg.Security.PreviousAuthToUserSecret, cfg.Security.PreviousUserToAuthSecret, service.Search.ReaderSecret, service.Search.WriterSecret, cfg.Services.Content.InternalSecret, service.Content.SearchSecret} {
			if key != "" && key == service.Content.PurgeSecret {
				return errors.New("content cleanup credential must be distinct")
			}
		}

		contentPublisher, err = contentcleanup.New(db, service.Content.URL, service.Content.PurgeSecret)

		if err != nil {
			return fmt.Errorf("content cleanup configuration: %w", err)
		}
	}

	if requirePeerCert {
		handler.ConfigureInternalTLS(peerTransport, service.TLS.ClientURI)
	} else {
		handler.ConfigureInternalTLS(peerTransport, "")
	}

	if service.Media.Secret != "" || service.Media.PreviousSecret != "" || service.Media.ClientURI != "" {
		for _, credential := range []string{service.Media.Secret, service.Media.PreviousSecret} {
			if credential == "" {
				continue
			}

			for _, other := range []string{authToUser, userToAuth, cfg.Security.PreviousAuthToUserSecret, cfg.Security.PreviousUserToAuthSecret, service.Search.ReaderSecret, service.Search.WriterSecret, service.Content.SearchSecret, service.Content.PurgeSecret, cfg.Services.Content.InternalSecret, cfg.Services.Content.PurgeSecret} {
				if other != "" && credential == other {
					return errors.New("media service credentials must be distinct")
				}
			}
		}

		if err := handler.ConfigureMediaService(service.Media.Secret, service.Media.PreviousSecret, service.Media.ClientURI); err != nil {
			return fmt.Errorf("media service configuration: %w", err)
		}
	}

	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	defer stopMaintenance()

	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-maintenanceCtx.Done():
				return
			case <-ticker.C:

				if service.RecoveryMode {
					continue
				}

				ctx, cancel := context.WithTimeout(maintenanceCtx, 5*time.Second)
				_, err := repo.PurgeStalePresence(ctx)
				cancel()

				if err != nil && maintenanceCtx.Err() == nil {
					log.Printf("cleanup presence: %v", err)
				}
			}
		}
	}()

	defer func() {
		stopMaintenance()
		<-cleanupDone
	}()

	if searchPublisher != nil && !service.RecoveryMode {
		publisherDone := make(chan struct{})
		go func() {
			defer close(publisherDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-maintenanceCtx.Done():
					return
				case <-ticker.C:

					for i := 0; i < 25; i++ {
						ctx, cancel := context.WithTimeout(maintenanceCtx, 8*time.Second)
						delivered, err := searchPublisher.DeliverOne(ctx)
						cancel()

						if err != nil {
							if maintenanceCtx.Err() == nil {
								log.Printf("search event delivery: %v", err)
							}

							break
						}

						if !delivered {
							break
						}
					}
				}
			}
		}()
		defer func() {
			stopMaintenance()
			<-publisherDone
		}()
	}

	if contentPublisher != nil && !service.RecoveryMode {
		publisherDone := make(chan struct{})
		go func() {
			defer close(publisherDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-maintenanceCtx.Done():
					return
				case <-ticker.C:

					for i := 0; i < 25; i++ {
						ctx, cancel := context.WithTimeout(maintenanceCtx, 8*time.Second)
						delivered, err := contentPublisher.DeliverOne(ctx)
						cancel()

						if err != nil {
							if maintenanceCtx.Err() == nil {
								log.Printf("content cleanup delivery: %v", err)
							}

							break
						}

						if !delivered {
							break
						}
					}
				}
			}
		}()
		defer func() {
			stopMaintenance()
			<-publisherDone
		}()
	}

	routes := handler.Routes()

	server := &http.Server{
		Addr:              net.JoinHostPort(service.Host, strconv.Itoa(service.Port)),
		Handler:           routes,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         serverTLS,
	}

	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	serverErrors := make(chan error, 1)
	go func() {
		if service.TLS.CertFile != "" {
			serverErrors <- server.ListenAndServeTLS(service.TLS.CertFile, service.TLS.KeyFile)
			return
		}

		serverErrors <- server.ListenAndServe()
	}()
	log.Printf("user listening on %s", server.Addr)

	select {
	case err := <-serverErrors:

		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: %w", err)
		}
	case <-stopped:
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}

	return nil
}
