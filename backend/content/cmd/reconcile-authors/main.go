package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	"mtls/content/internal/reconcile"
	sharedconfig "mtls/shared/config"
)

type settings struct {
	Database struct {
		Driver   string `toml:"driver"`
		Port     int    `toml:"port"`
		SSLMode  string `toml:"sslmode"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	} `toml:"database"`
	Services struct {
		Auth struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"auth"`
		Content struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"content"`
	} `toml:"services"`
}

type serviceDatabase struct {
	Host              string  `toml:"host"`
	Name              string  `toml:"name"`
	User              string  `toml:"user"`
	Password          *string `toml:"password"`
	MigrationUser     string  `toml:"migration_user"`
	MigrationPassword *string `toml:"migration_password"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "config.toml", "path to configuration")
	isolated := flag.Bool("isolated", false, "confirm all auth and content clients are stopped and isolated")
	verified := flag.Bool("verified-auth", false, "confirm auth is current, complete and independently verified")
	apply := flag.Bool("apply", false, "delete posts and reactions of accounts absent from verified auth")
	flag.Parse()

	if !*isolated || !*verified {
		return errors.New("stop and isolate all clients, independently verify auth completeness, then pass -isolated -verified-auth")
	}

	var cfg settings

	if err := sharedconfig.Load(*path, &cfg); err != nil {
		return errors.New("cannot load configuration")
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 {
		return errors.New("invalid database settings")
	}

	auth, err := openDB(cfg, cfg.Services.Auth.Database)

	if err != nil {
		return fmt.Errorf("open auth database: %w", err)
	}

	defer auth.Close()
	content, err := openDB(cfg, cfg.Services.Content.Database)

	if err != nil {
		return fmt.Errorf("open content database: %w", err)
	}

	defer content.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := auth.PingContext(ctx); err != nil {
		return errors.New("auth database unavailable")
	}

	if err := content.PingContext(ctx); err != nil {
		return errors.New("content database unavailable")
	}

	count, err := reconcile.Offline(ctx, auth, content, *apply)

	if err != nil {
		return fmt.Errorf("reconciliation failed; keep services isolated: %w", err)
	}

	if !*apply {
		fmt.Printf("Dry run: %d content accounts absent from verified auth; no data removed.\n", count)
		return nil
	}

	fmt.Printf("Removed posts and reactions for %d accounts absent from verified auth.\n", count)
	return nil
}

func openDB(cfg settings, db serviceDatabase) (*sql.DB, error) {
	if db.Host == "" || db.Name == "" {
		return nil, errors.New("database host and name required")
	}

	mode := cfg.Database.SSLMode

	if mode == "" {
		mode = "verify-full"
	}

	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return nil, errors.New("invalid database TLS mode")
	}

	if err := sharedconfig.ValidateDatabaseTLS(db.Host, mode); err != nil {
		return nil, err
	}

	username, password, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, db.User, db.Password)

	if db.MigrationUser != "" || db.MigrationPassword != nil {
		username, password, err = sharedconfig.ResolveDatabaseCredentials("", "", db.MigrationUser, db.MigrationPassword)
	}

	if err != nil {
		return nil, errors.New("invalid database credentials")
	}

	address := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(db.Host, strconv.Itoa(cfg.Database.Port)),
		Path:   "/" + db.Name,
	}

	query := address.Query()
	query.Set("sslmode", mode)
	address.RawQuery = query.Encode()
	return sql.Open("postgres", address.String())
}
