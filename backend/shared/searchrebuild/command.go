package searchrebuild

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

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
		User struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"user"`
		Content struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"content"`
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

func Run(kind string) error {
	path := flag.String("config", "config.toml", "path to configuration")
	isolated := flag.Bool("isolated", false, "confirm all source publishers and search writers are stopped and isolated")
	flag.Parse()

	if !*isolated {
		return errors.New("stop and isolate all source publishers and search writers; then pass -isolated")
	}

	var cfg settings

	if err := sharedconfig.Load(*path, &cfg); err != nil {
		return errors.New("cannot load configuration")
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 {
		return errors.New("invalid database settings")
	}

	sourceSettings := cfg.Services.User.Database
	if kind == "content" {
		sourceSettings = cfg.Services.Content.Database
	}
	source, err := openDB(cfg, sourceSettings)

	if err != nil {
		return fmt.Errorf("open source database: %w", err)
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
		return errors.New("source database unavailable")
	}

	if err := index.PingContext(ctx); err != nil {
		return errors.New("search database unavailable")
	}

	count, err := RebuildOffline(ctx, source, index, kind)

	if err != nil {
		return fmt.Errorf("rebuild failed; keep services isolated and retry: %w", err)
	}

	fmt.Printf("Queued %d %s records for search indexing. Start search and the source publisher, then verify the queue drains.\n", count, kind)
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
