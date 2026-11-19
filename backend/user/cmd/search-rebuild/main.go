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
	sharedconfig "mtls/shared/config"
	"mtls/user/internal/searchindex"
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
		User struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"user"`
		Search struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"search"`
	} `toml:"services"`
}

type serviceDatabase struct {
	Host              string  `toml:"host"`
	Name              string  `toml:"name"`
	SSLMode           string  `toml:"sslmode"`
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
	isolated := flag.Bool("isolated", false, "confirm all user publishers and search writers are stopped and isolated")
	flag.Parse()

	if !*isolated {
		return errors.New("stop and isolate all user publishers and search writers; then pass -isolated")
	}

	var cfg settings

	if err := sharedconfig.Load(*path, &cfg); err != nil {
		return errors.New("cannot load configuration")
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 {
		return errors.New("invalid database settings")
	}

	source, err := openDB(cfg, cfg.Services.User.Database)

	if err != nil {
		return fmt.Errorf("open user database: %w", err)
	}

	defer source.Close()
	index, err := openDB(cfg, cfg.Services.Search.Database)

	if err != nil {
		return fmt.Errorf("open search database: %w", err)
	}

	defer index.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := source.PingContext(ctx); err != nil {
		return errors.New("user database unavailable")
	}

	if err := index.PingContext(ctx); err != nil {
		return errors.New("search database unavailable")
	}

	count, err := searchindex.RebuildOffline(ctx, source, index)

	if err != nil {
		return fmt.Errorf("rebuild failed; keep services isolated and retry: %w", err)
	}

	fmt.Printf("Queued %d user profiles for search indexing. Start search, then user, and verify the queue drains.\n", count)
	return nil
}

func openDB(cfg settings, db serviceDatabase) (*sql.DB, error) {
	if db.Host == "" || db.Name == "" {
		return nil, errors.New("database host and name required")
	}

	mode := db.SSLMode

	if mode == "" {
		mode = cfg.Database.SSLMode
	}

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
