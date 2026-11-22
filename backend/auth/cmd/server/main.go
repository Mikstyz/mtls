package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	_ "github.com/lib/pq"
	"go.uber.org/automaxprocs/maxprocs"

	"mtls/auth/internal/config"
	"mtls/auth/internal/httpapi"
	"mtls/auth/internal/mailer"
	"mtls/auth/internal/redisshield"
	"mtls/auth/internal/securityevents"
	sharedconfig "mtls/shared/config"
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
	service := cfg.Services.Auth

	if err := sharedconfig.RequireMutualTLSForRemote(service.User.URL, service.TLS); err != nil {
		return fmt.Errorf("peer TLS configuration: %w", err)
	}

	serverTLS, requirePeerCert, err := service.TLS.ServerConfig()

	if err != nil {
		return fmt.Errorf("server TLS configuration: %w", err)
	}

	peerTransport, err := service.TLS.ClientTransport(service.User.URL)

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

	const schemaCheck = `SELECT c.enabled, c.email_verified, c.password_revision, s.token_hash, s.recovery_generation,
		a.key_hash, r.token_hash, r.provision_lease_id, j.token_ciphertext, p.purpose, p.email, p.pending_email,
		d.state, roles.role, events.outcome, session_history.last_seen_at
		FROM credentials c, sessions s, login_attempts a, registrations r, registration_mail_jobs j,
			password_resets p, account_deletions d, account_roles roles, account_moderation_events events,
			user_session_history session_history
		LIMIT 0`

	rows, err := db.QueryContext(ctx, schemaCheck)

	if err != nil {
		return fmt.Errorf("database schema is incomplete: %w", err)
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("check database schema: %w", err)
	}

	var purgeIndexPresent, sessionIndexPresent, idleIndexPresent, roleTriggerPresent bool

	if err := db.QueryRowContext(ctx, `SELECT to_regclass('account_deletions_purge_deadline_idx') IS NOT NULL,
		to_regclass('sessions_revoked_at_idx') IS NOT NULL,
		to_regclass('sessions_last_seen_at_idx') IS NOT NULL,
		(SELECT count(*) = 2 FROM pg_trigger WHERE tgrelid = 'account_roles'::regclass
			AND tgname IN ('account_roles_revoke_sessions', 'account_roles_revoke_sessions_on_truncate')
			AND NOT tgisinternal AND tgenabled IN ('O', 'A'))`).Scan(
		&purgeIndexPresent, &sessionIndexPresent, &idleIndexPresent, &roleTriggerPresent,
	); err != nil {
		return fmt.Errorf("check database schema: %w", err)
	}

	if !purgeIndexPresent {
		return errors.New("database schema is incomplete: account purge index is missing")
	}

	if !sessionIndexPresent || !idleIndexPresent {
		return errors.New("database schema is incomplete: session cleanup index is missing")
	}

	if !roleTriggerPresent {
		return errors.New("database schema is incomplete: role session revocation trigger is missing")
	}

	var sessionEpochPresent bool

	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM session_epoch WHERE id AND generation >= 0)`).Scan(&sessionEpochPresent); err != nil {
		return fmt.Errorf("check session recovery epoch: %w", err)
	}

	if !sessionEpochPresent {
		return errors.New("database schema is incomplete: session recovery epoch is missing")
	}

	var credentialStateTriggerPresent bool

	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger
		WHERE tgrelid = 'credentials'::regclass AND tgname = 'credentials_state_revoke_sessions'
			AND NOT tgisinternal AND tgenabled IN ('O', 'A'))`).Scan(&credentialStateTriggerPresent); err != nil {
		return fmt.Errorf("check credential state trigger: %w", err)
	}

	if !credentialStateTriggerPresent {
		return errors.New("database schema is incomplete: credential state session revocation trigger is missing")
	}

	var outboxReady bool

	if err := db.QueryRowContext(ctx, `SELECT
		to_regclass('security_event_outbox') IS NOT NULL AND
		to_regclass('security_event_versions') IS NOT NULL AND
		(SELECT count(*) = 7 FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN ('O', 'A') AND
			((tgrelid = 'credentials'::regclass AND tgname IN ('credentials_security_event_update', 'credentials_security_event_delete')) OR
			 (tgrelid = 'sessions'::regclass AND tgname IN ('sessions_security_event_revocation', 'sessions_security_event_delete')) OR
			 (tgrelid = 'account_roles'::regclass AND tgname IN ('account_roles_security_event', 'account_roles_security_event_truncate')) OR
			 (tgrelid = 'account_deletions'::regclass AND tgname = 'account_deletions_security_event')))`).Scan(&outboxReady); err != nil {
		return fmt.Errorf("check security event schema: %w", err)
	}

	if !outboxReady {
		return errors.New("database schema is incomplete: security event outbox or triggers are missing")
	}

	var outboxAccess bool

	if err := db.QueryRowContext(ctx, `SELECT
		has_table_privilege(current_user, 'security_event_outbox', 'SELECT') AND
		has_table_privilege(current_user, 'security_event_outbox', 'INSERT') AND
		has_column_privilege(current_user, 'security_event_outbox', 'published_at', 'UPDATE') AND
		has_column_privilege(current_user, 'security_event_outbox', 'lease_id', 'UPDATE') AND
		has_column_privilege(current_user, 'security_event_outbox', 'lease_until', 'UPDATE') AND
		has_column_privilege(current_user, 'security_event_outbox', 'available_at', 'UPDATE') AND
		has_column_privilege(current_user, 'security_event_outbox', 'attempts', 'UPDATE') AND
		has_table_privilege(current_user, 'security_event_versions', 'SELECT') AND
		has_table_privilege(current_user, 'security_event_versions', 'INSERT') AND
		has_column_privilege(current_user, 'security_event_versions', 'version', 'UPDATE') AND
		has_function_privilege(current_user, 'append_security_event(uuid,text,text,timestamp with time zone)', 'EXECUTE')`).Scan(&outboxAccess); err != nil {
		return fmt.Errorf("check security event permissions: %w", err)
	}

	if !outboxAccess {
		return errors.New("database permissions are incomplete: security event outbox access is missing")
	}

	authToUser, userToAuth, err := sharedconfig.ResolveInternalSecrets(service.User.URL, cfg.Security.InternalSecret, cfg.Security.AuthToUserSecret, cfg.Security.UserToAuthSecret)

	if err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	if err := sharedconfig.ValidateRateLimitSecret(service.User.URL, cfg.Security.RateLimitSecret, authToUser, userToAuth); err != nil {
		return fmt.Errorf("rate-limit credential: %w", err)
	}

	if err := sharedconfig.ValidateInternalSecretRotation(authToUser, userToAuth, cfg.Security.PreviousAuthToUserSecret, cfg.Security.PreviousUserToAuthSecret); err != nil {
		return fmt.Errorf("internal service credential rotation: %w", err)
	}

	if cfg.Security.RateLimitSecret != "" && (cfg.Security.RateLimitSecret == cfg.Security.PreviousAuthToUserSecret || cfg.Security.RateLimitSecret == cfg.Security.PreviousUserToAuthSecret) {
		return errors.New("rate-limit credential must differ from previous service credentials")
	}

	handler, err := httpapi.New(db, cfg.HTTP.AllowedOrigin, cfg.HTTP.CookieSecure, userToAuth, service.User.URL)

	if err != nil {
		return fmt.Errorf("http configuration: %w", err)
	}

	if err := handler.SetUserServiceSecret(authToUser); err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	if err := handler.ConfigureSecretRotation(cfg.Security.PreviousUserToAuthSecret, cfg.Security.RateLimitSecret); err != nil {
		return fmt.Errorf("internal service credentials: %w", err)
	}

	guard, err := redisshield.Open(redisshield.Config{
		Address: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password,
		TLS: cfg.Redis.TLS, CAFile: cfg.Redis.CAFile,
		SentinelMaster: cfg.Redis.SentinelMaster, SentinelAddrs: cfg.Redis.SentinelAddrs,
		SentinelUsername: cfg.Redis.SentinelUsername, SentinelPassword: cfg.Redis.SentinelPassword,
	})

	if err != nil {
		return fmt.Errorf("redis rate guard: %w", err)
	}

	if guard != nil {
		defer guard.Close()
	}

	kafkaCA := cfg.Kafka.CAFile

	if kafkaCA != "" && !filepath.IsAbs(kafkaCA) {
		kafkaCA = filepath.Join(filepath.Dir(*configPath), kafkaCA)
	}

	kafka, err := securityevents.OpenKafka(securityevents.KafkaConfig{
		Brokers: cfg.Kafka.Brokers, Topic: cfg.Kafka.Topic, TLS: cfg.Kafka.TLS,
		CAFile: kafkaCA, Username: cfg.Kafka.Username, Password: cfg.Kafka.Password,
	})

	if err != nil {
		return fmt.Errorf("kafka security events: %w", err)
	}

	if kafka != nil {
		defer kafka.Close()
	}

	if guard != nil {
		handler.SetRateGuard(guard)

		if cfg.Redis.SessionCache {
			cacheSecret := cfg.Security.RateLimitSecret

			if cacheSecret == "" {
				cacheSecret = userToAuth
			}

			cache, err := guard.NewSessionCache(cacheSecret)

			if err != nil {
				return fmt.Errorf("redis session cache: %w", err)
			}

			handler.SetSessionCache(cache)
		}
	}

	if requirePeerCert {
		handler.ConfigureInternalTLS(peerTransport, service.TLS.ClientURI)
	} else {
		handler.ConfigureInternalTLS(peerTransport, "")
	}

	handler.SetPasswordNormalization(service.Password.NormalizeUnicode)
	handler.SetRecoveryMode(service.RecoveryMode)

	if service.RecoveryMode {
		log.Print("auth recovery mode: requests and background processing are disabled")
	}

	if service.Password.BlocklistPath != "" {
		blocklistPath := service.Password.BlocklistPath

		if !filepath.IsAbs(blocklistPath) {
			blocklistPath = filepath.Join(filepath.Dir(*configPath), blocklistPath)
		}

		if err := handler.LoadPasswordBlocklist(blocklistPath); err != nil {
			return fmt.Errorf("password blocklist: %w", err)
		}
	}

	registration := service.Registration
	registrationEnabled := registration.DeliveryKey != "" || registration.PreviousDeliveryKey != "" || registration.SMTPHost != "" || registration.SMTPCaFile != "" || registration.SMTPPort != 0 || registration.SMTPUser != "" || registration.SMTPPassword != "" || registration.From != ""

	if registrationEnabled {
		key, err := base64.StdEncoding.DecodeString(registration.DeliveryKey)

		if err != nil {
			return errors.New("registration delivery key must be base64 encoded")
		}

		smtpCA := registration.SMTPCaFile

		if smtpCA != "" && !filepath.IsAbs(smtpCA) {
			smtpCA = filepath.Join(filepath.Dir(*configPath), smtpCA)
		}

		transport := mailer.SMTP{
			Host: registration.SMTPHost, Port: registration.SMTPPort, CAFile: smtpCA,
			Username: registration.SMTPUser, Password: registration.SMTPPassword,
			From: registration.From, Origin: cfg.HTTP.AllowedOrigin,
		}

		if err := handler.ConfigureRegistration(key, transport); err != nil {
			return fmt.Errorf("registration configuration: %w", err)
		}

		if registration.PreviousDeliveryKey != "" {
			previousKey, err := base64.StdEncoding.DecodeString(registration.PreviousDeliveryKey)

			if err != nil {
				return errors.New("previous registration delivery key must be base64 encoded")
			}

			if err := handler.SetPreviousDeliveryKey(previousKey); err != nil {
				return fmt.Errorf("registration configuration: %w", err)
			}
		}
	}

	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	registrationDone := make(chan struct{})
	lifecycleDone := make(chan struct{})
	eventsDone := make(chan struct{})

	go func() {
		defer close(registrationDone)
		handler.RunRegistration(maintenanceCtx)
	}()

	go func() {
		defer close(lifecycleDone)
		handler.RunAccountLifecycle(maintenanceCtx)
	}()

	go func() {
		defer close(eventsDone)

		if kafka != nil && !service.RecoveryMode {
			securityevents.NewRelay(securityevents.NewStore(db), kafka).Run(maintenanceCtx)
		}
	}()

	defer func() {
		stopMaintenance()
		<-registrationDone
		<-lifecycleDone
		<-eventsDone
	}()

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
				err := handler.CleanupLoginAttempts(ctx)
				cancel()

				if err != nil && maintenanceCtx.Err() == nil {
					log.Printf("cleanup login attempts: %v", err)
				}

				ctx, cancel = context.WithTimeout(maintenanceCtx, 5*time.Second)
				err = handler.CleanupSessions(ctx)
				cancel()

				if err != nil && maintenanceCtx.Err() == nil {
					log.Printf("cleanup sessions: %v", err)
				}

				if registrationEnabled {
					ctx, cancel := context.WithTimeout(maintenanceCtx, 5*time.Second)
					err := handler.CleanupRegistrations(ctx)
					cancel()

					if err != nil && maintenanceCtx.Err() == nil {
						log.Printf("cleanup registrations: %v", err)
					}
				}
			}
		}
	}()

	defer func() {
		stopMaintenance()
		<-cleanupDone
	}()

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
	log.Printf("auth listening on %s", server.Addr)

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
