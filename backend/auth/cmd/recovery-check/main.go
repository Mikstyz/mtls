package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"mtls/auth/internal/recovery"
	sharedconfig "mtls/shared/config"
)

type database struct {
	Host     string  `toml:"host"`
	Name     string  `toml:"name"`
	User     string  `toml:"user"`
	Password *string `toml:"password"`
}

type service struct {
	RecoveryMode bool     `toml:"recovery_mode"`
	Database     database `toml:"database"`
}

type config struct {
	Database struct {
		Driver   string `toml:"driver"`
		Port     int    `toml:"port"`
		SSLMode  string `toml:"sslmode"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	} `toml:"database"`
	Services struct {
		Auth service `toml:"auth"`
		User service `toml:"user"`
	} `toml:"services"`
}

func main() {
	if err := run(); err != nil {
		log.Print(err)

		if errors.Is(err, recovery.ErrCompletenessUnproven) {
			os.Exit(2)
		}

		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "config.toml", "path to TOML configuration")
	issueFile := flag.String("issue-file", "", "create a private file with the first conflicting user ID")
	invalidateSessions := flag.Bool("invalidate-sessions", false, "invalidate sessions in an isolated restored auth database")
	flag.Parse()

	if *invalidateSessions && *issueFile != "" {
		return errors.New("issue-file cannot be combined with session invalidation")
	}

	var cfg config
	if err := sharedconfig.Load(*path, &cfg); err != nil {
		return err
	}

	if !cfg.Services.Auth.RecoveryMode || !cfg.Services.User.RecoveryMode {
		return errors.New("auth and user recovery modes must both be enabled")
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 {
		return errors.New("invalid database settings")
	}

	mode := cfg.Database.SSLMode
	if mode == "" {
		mode = "verify-full"
	}

	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return errors.New("invalid database TLS mode")
	}

	open := func(settings database) (*sql.DB, error) {
		if strings.TrimSpace(settings.Host) == "" || strings.TrimSpace(settings.Name) == "" {
			return nil, errors.New("database host and name are required")
		}

		if err := sharedconfig.ValidateDatabaseTLS(settings.Host, mode); err != nil {
			return nil, err
		}

		user, password, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, settings.User, settings.Password)
		if err != nil {
			return nil, errors.New("invalid database credentials")
		}

		address := &url.URL{Scheme: "postgres", User: url.UserPassword(user, password),
			Host: net.JoinHostPort(settings.Host, strconv.Itoa(cfg.Database.Port)), Path: "/" + settings.Name}
		query := address.Query()
		query.Set("sslmode", mode)
		address.RawQuery = query.Encode()

		db, err := sql.Open("postgres", address.String())
		if err != nil {
			return nil, errors.New("cannot configure database connection")
		}

		return db, nil
	}

	auth, err := open(cfg.Services.Auth.Database)
	if err != nil {
		return fmt.Errorf("configure auth database: %w", err)
	}

	defer auth.Close()

	users, err := open(cfg.Services.User.Database)
	if err != nil {
		return fmt.Errorf("configure user database: %w", err)
	}

	defer users.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if *invalidateSessions {
		if err := recovery.InvalidateRestoredSessions(ctx, auth); err != nil {
			return err
		}

		log.Print("restored sessions invalidated; keep both services in recovery mode")
		return nil
	}

	result, err := recovery.CheckAccounts(ctx, auth, users)
	if err != nil {
		var issue *recovery.AccountIssue

		if *issueFile != "" && errors.As(err, &issue) {
			if writeErr := recovery.WritePrivateReport(*issueFile, issue); writeErr != nil {
				return fmt.Errorf("write private issue file: %w", writeErr)
			}
		}

		return fmt.Errorf("check auth and user accounts: %w", err)
	}

	log.Printf("checked %d accounts; %d operations remain pending", result.Accounts, result.Pending)
	if result.Pending != 0 {
		return errors.New("pending account operations need reconciliation; keep recovery mode enabled")
	}

	return recovery.ErrCompletenessUnproven
}
