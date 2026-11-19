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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"mtls/auth/internal/recovery"
	"mtls/auth/internal/securityevents"
	sharedconfig "mtls/shared/config"
)

type config struct {
	Database struct {
		Driver   string `toml:"driver"`
		Port     int    `toml:"port"`
		SSLMode  string `toml:"sslmode"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	} `toml:"database"`
	Services struct {
		Auth struct {
			RecoveryMode bool `toml:"recovery_mode"`
			Database     struct {
				Host     string  `toml:"host"`
				Name     string  `toml:"name"`
				User     string  `toml:"user"`
				Password *string `toml:"password"`
			} `toml:"database"`
		} `toml:"auth"`
		SecurityJournal struct {
			Database struct {
				Host     string  `toml:"host"`
				Name     string  `toml:"name"`
				User     string  `toml:"user"`
				Password *string `toml:"password"`
			} `toml:"database"`
			Kafka securityevents.KafkaConfig `toml:"kafka"`
		} `toml:"security_journal"`
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
	configPath := flag.String("config", "config.toml", "path to TOML configuration")
	checkVersions := flag.Bool("check-versions", false, "check archived per-user version gaps and exit")
	compareSource := flag.Bool("compare-source", false, "compare an isolated auth snapshot with the journal and exit")
	issueFile := flag.String("issue-file", "", "create a private file with the first journal difference")
	flag.Parse()

	if *checkVersions && *compareSource {
		return errors.New("choose only one journal check")
	}

	if *issueFile != "" && !*compareSource {
		return errors.New("issue-file requires source comparison")
	}

	var cfg config

	if err := sharedconfig.Load(*configPath, &cfg); err != nil {
		return err
	}

	service := cfg.Services.SecurityJournal

	if service.Kafka.CAFile != "" && !filepath.IsAbs(service.Kafka.CAFile) {
		service.Kafka.CAFile = filepath.Join(filepath.Dir(*configPath), service.Kafka.CAFile)
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 ||
		strings.TrimSpace(service.Database.Host) == "" || strings.TrimSpace(service.Database.Name) == "" {
		return errors.New("invalid security journal database settings")
	}

	user, password, err := sharedconfig.ResolveDatabaseCredentials(
		cfg.Database.User, cfg.Database.Password, service.Database.User, service.Database.Password,
	)

	if err != nil {
		return errors.New("invalid security journal database credentials")
	}

	mode := cfg.Database.SSLMode

	if mode == "" {
		mode = "verify-full"
	}

	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return errors.New("invalid security journal database TLS mode")
	}

	if err := sharedconfig.ValidateDatabaseTLS(service.Database.Host, mode); err != nil {
		return err
	}

	address := &url.URL{
		Scheme: "postgres", User: url.UserPassword(user, password),
		Host: net.JoinHostPort(service.Database.Host, strconv.Itoa(cfg.Database.Port)), Path: "/" + service.Database.Name,
	}
	query := address.Query()
	query.Set("sslmode", mode)
	address.RawQuery = query.Encode()

	db, err := sql.Open("postgres", address.String())

	if err != nil {
		return errors.New("cannot configure security journal database")
	}
	defer db.Close()

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = db.PingContext(checkCtx)
	cancel()

	if err != nil {
		return errors.New("cannot connect to security journal database")
	}

	if *compareSource {
		if !cfg.Services.Auth.RecoveryMode {
			return errors.New("source comparison requires services.auth.recovery_mode = true")
		}

		source := cfg.Services.Auth.Database

		if strings.TrimSpace(source.Host) == "" || strings.TrimSpace(source.Name) == "" {
			return errors.New("invalid auth source database settings")
		}

		if err := sharedconfig.ValidateDatabaseTLS(source.Host, mode); err != nil {
			return err
		}

		sourceUser, sourcePassword, err := sharedconfig.ResolveDatabaseCredentials(
			cfg.Database.User, cfg.Database.Password, source.User, source.Password,
		)

		if err != nil {
			return errors.New("invalid auth source database credentials")
		}

		sourceAddress := &url.URL{
			Scheme: "postgres", User: url.UserPassword(sourceUser, sourcePassword),
			Host: net.JoinHostPort(source.Host, strconv.Itoa(cfg.Database.Port)), Path: "/" + source.Name,
		}
		sourceQuery := sourceAddress.Query()
		sourceQuery.Set("sslmode", mode)
		sourceAddress.RawQuery = sourceQuery.Encode()

		sourceDB, err := sql.Open("postgres", sourceAddress.String())

		if err != nil {
			return errors.New("cannot configure auth source database")
		}
		defer sourceDB.Close()

		compareCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		result, err := securityevents.CompareRecoverySource(compareCtx, sourceDB, db)

		if err != nil {
			var issue *securityevents.RecoveryIssue

			if *issueFile != "" && errors.As(err, &issue) {
				if writeErr := recovery.WritePrivateReport(*issueFile, issue); writeErr != nil {
					return fmt.Errorf("write private issue file: %w", writeErr)
				}
			}

			return fmt.Errorf("compare auth source with journal: %w", err)
		}

		log.Printf("compared %d source events; %d events are present only in the journal", result.SourceEvents, result.JournalOnlyEvents)

		if result.JournalOnlyEvents != 0 {
			if *issueFile != "" && result.FirstJournalOnly != nil {
				if err := recovery.WritePrivateReport(*issueFile, result.FirstJournalOnly); err != nil {
					return fmt.Errorf("write private issue file: %w", err)
				}
			}

			return errors.New("journal has changes missing from the auth snapshot; keep recovery mode enabled")
		}

		return recovery.ErrCompletenessUnproven
	}

	if *checkVersions {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		if err := securityevents.NewJournal(db).CheckVersions(checkCtx); err != nil {
			return fmt.Errorf("security journal version check: %w", err)
		}

		log.Print("no internal security journal version gaps detected; source completeness is not proven")
		return nil
	}

	startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	consumer, err := securityevents.NewJournalConsumer(startupCtx, db, service.Kafka)
	cancel()

	if err != nil {
		return fmt.Errorf("initialize security journal: %w", err)
	}
	defer consumer.Close()

	log.Print("security journal consumer started")

	if err := consumer.Run(ctx); err != nil {
		return fmt.Errorf("security journal stopped: %w", err)
	}

	return nil
}
