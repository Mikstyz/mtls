// Command search-publisher sends the transactional content outbox to search.
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
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"mtls/content/internal/config"
	"mtls/content/internal/searchindex"
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
		return fmt.Errorf("load configuration: %w", err)
	}

	service := cfg.Services.Content
	settings := service.Search

	if service.RecoveryMode {
		return errors.New("content recovery mode forbids search delivery")
	}

	contentUser, _, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, service.Database.User, service.Database.Password)

	if err != nil {
		return errors.New("invalid content database credentials")
	}

	if settings.DatabaseUser == "" || settings.DatabasePassword == nil || settings.DatabaseUser == contentUser || settings.DatabaseUser == service.Database.PurgeUser {
		return errors.New("a separate search publisher database role is required")
	}

	mode := cfg.Database.SSLMode

	if mode == "" {
		mode = "verify-full"
	}

	address := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(settings.DatabaseUser, *settings.DatabasePassword),
		Host:   net.JoinHostPort(service.Database.Host, strconv.Itoa(cfg.Database.Port)),
		Path:   "/" + service.Database.Name,
	}
	query := address.Query()
	query.Set("sslmode", mode)
	address.RawQuery = query.Encode()

	db, err := sql.Open("postgres", address.String())

	if err != nil {
		return errors.New("cannot initialize publisher database")
	}

	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return errors.New("publisher database unavailable")
	}

	if err := validatePrivileges(ctx, db); err != nil {
		return err
	}

	publisher, err := searchindex.New(db, settings.URL, settings.WriterSecret)

	if err != nil {
		return fmt.Errorf("configure search publisher: %w", err)
	}

	stop, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	for stop.Err() == nil {
		processed, err := publisher.DeliverOne(stop)

		if stop.Err() != nil {
			break
		}

		delay := time.Duration(0)

		if err != nil {
			log.Print("content search delivery failed")
			delay = 5 * time.Second
		} else if !processed {
			delay = time.Second
		}

		if delay > 0 {
			timer := time.NewTimer(delay)

			select {
			case <-stop.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}

	return nil
}
