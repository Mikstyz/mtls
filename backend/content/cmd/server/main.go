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
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"mtls/content/internal/catalog"
	"mtls/content/internal/config"
	"mtls/content/internal/httpapi"
	sharedconfig "mtls/shared/config"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "config.toml", "path to TOML configuration")
	flag.Parse()
	cfg, err := config.Load(*path)

	if err != nil {
		return fmt.Errorf("load content configuration: %w", err)
	}

	if cfg.Resources.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.Resources.MaxProcs)
	}

	if cfg.Resources.MemoryLimitBytes > 0 {
		debug.SetMemoryLimit(cfg.Resources.MemoryLimitBytes)
	}

	service := cfg.Services.Content
	user, password, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, service.Database.User, service.Database.Password)

	if err != nil {
		return errors.New("invalid database credentials")
	}

	mode := cfg.Database.SSLMode

	if mode == "" {
		mode = "verify-full"
	}

	address := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(service.Database.Host, strconv.Itoa(cfg.Database.Port)),
		Path:   "/" + service.Database.Name,
	}
	query := address.Query()
	query.Set("sslmode", mode)
	address.RawQuery = query.Encode()
	db, err := sql.Open("postgres", address.String())

	if err != nil {
		return errors.New("cannot initialize database")
	}

	defer db.Close()
	maxOpen := cfg.Database.MaxOpenConns

	if maxOpen == 0 {
		maxOpen = 10
	}

	maxIdle := cfg.Database.MaxIdleConns

	if maxIdle == 0 {
		maxIdle = 2
	}

	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return errors.New("content database unavailable")
	}

	rows, err := db.QueryContext(ctx, `SELECT p.id,p.author_id,p.media_kind,p.visibility,p.status,p.published_at,p.revision,m.media_id,d.request_id,a.author_id FROM content_posts p, content_post_media m, content_draft_requests d, content_author_purges a LIMIT 0`)

	if err != nil {
		return errors.New("content database schema incomplete")
	}

	if err := rows.Close(); err != nil {
		return errors.New("content database schema check failed")
	}

	if err := validateRuntimePrivileges(ctx, db); err != nil {
		return err
	}

	if err := validateSalesPrivileges(ctx, db, service.TestSales, false); err != nil {
		return err
	}

	var purger httpapi.Purger
	purgeConfigured := service.PurgeSecret != "" || service.PreviousPurgeSecret != "" || service.Database.PurgeUser != "" || service.Database.PurgePassword != nil
	if purgeConfigured {
		if service.PurgeSecret == "" || service.Database.PurgeUser == "" || service.Database.PurgePassword == nil || service.Database.PurgeUser == user {
			return errors.New("separate purge database credentials and purge secret are required")
		}

		purgeAddress := *address
		purgeAddress.User = url.UserPassword(service.Database.PurgeUser, *service.Database.PurgePassword)
		purgeDB, err := sql.Open("postgres", purgeAddress.String())
		if err != nil {
			return errors.New("cannot initialize purge database")
		}
		defer purgeDB.Close()
		purgeDB.SetMaxOpenConns(2)
		purgeDB.SetMaxIdleConns(1)
		purgeDB.SetConnMaxLifetime(30 * time.Minute)

		if err := purgeDB.PingContext(ctx); err != nil {
			return errors.New("content purge database unavailable")
		}
		if err := validatePurgePrivileges(ctx, purgeDB); err != nil {
			return err
		}
		if err := validateSalesPrivileges(ctx, purgeDB, false, true); err != nil {
			return err
		}
		purger = catalog.New(purgeDB)
	}

	store := catalog.New(db)
	if service.TestSales {
		store = catalog.NewWithTestSales(db)
	}
	handler, err := httpapi.NewConfigured(store, purger, service.InternalSecret, service.PreviousInternalSecret, service.User.URL, service.User.CookieName, service.PurgeSecret, service.PreviousPurgeSecret, service.MediaViewSecret, service.User.TLS, httpapi.CoverFramePeer{URL: service.Media.URL, Secret: service.Media.Secret}, httpapi.DeliverySecrets{ProfilePoints: service.ProfilePointsSecret, MediaRevocation: service.MediaRevocationSecret})

	if err != nil {
		return err
	}

	if service.RecoveryMode {
		log.Print("content recovery mode: requests are disabled")
		handler = httpapi.RecoveryMode(handler)
	} else {
		stopPruning := startViewReceiptPruning(db)
		defer stopPruning()
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(service.Host, strconv.Itoa(service.Port)))

	if err != nil {
		return fmt.Errorf("listen content: %w", err)
	}

	defer listener.Close()

	stop, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if !service.RecoveryMode && service.User.URL != "" {
		publicationSecret := service.User.PublicationSecret
		if service.User.TLS.PeerCertFile == "" {
			if publicationSecret != "" {
				return errors.New("separate scheduled publication credential requires mutual TLS")
			}

			publicationSecret = service.InternalSecret
		} else {
			for _, secret := range []string{service.InternalSecret, service.PreviousInternalSecret, service.PurgeSecret, service.PreviousPurgeSecret, service.MediaViewSecret, service.ProfilePointsSecret, service.MediaRevocationSecret} {
				if secret != "" && publicationSecret == secret {
					return errors.New("scheduled publication credential must be distinct")
				}
			}
		}

		stopSchedules, err := httpapi.StartScheduledPosts(stop, store, service.User.URL, service.User.CookieName, publicationSecret, service.User.TLS)
		if err != nil {
			return err
		}
		defer stopSchedules()
	}

	maxConnections := service.MaxConnections

	if maxConnections == 0 {
		maxConnections = 128
	}

	listener = &limitedListener{Listener: listener, slots: make(chan struct{}, maxConnections)}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()
	select {
	case err := <-done:

		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("content server: %w", err)
		}
	case <-stop.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("content shutdown: %w", err)
		}
	}

	return nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()

		if err != nil {
			return nil, err
		}

		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, slots: l.slots}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		<-c.slots
	})
	return err
}
