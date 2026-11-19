package migrate

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"io/fs"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mtls/shared/config"
)

type commandConfig struct {
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
		User struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"user"`
		Content struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"content"`
		MediaProcessing struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"media_processing"`
		SecurityJournal struct {
			Database serviceDatabase `toml:"database"`
		} `toml:"security_journal"`
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

// RunCommand loads only the database settings needed for an explicit migration.
func RunCommand(service, sentinel string, files fs.FS) error {
	path := flag.String("config", "config.toml", "path to the configuration file")
	flag.Parse()

	var cfg commandConfig
	if err := config.Load(*path, &cfg); err != nil {
		return err
	}

	var database serviceDatabase

	switch service {
	case "auth":
		database = cfg.Services.Auth.Database
	case "user":
		database = cfg.Services.User.Database
	case "content":
		database = cfg.Services.Content.Database
	case "media_processing":
		database = cfg.Services.MediaProcessing.Database
	case "security_journal":
		database = cfg.Services.SecurityJournal.Database
	default:
		return errors.New("unsupported migration service")
	}

	var databaseUser, databasePassword string
	var err error

	if database.MigrationUser != "" || database.MigrationPassword != nil {
		databaseUser, databasePassword, err = config.ResolveDatabaseCredentials("", "", database.MigrationUser, database.MigrationPassword)
	} else {
		databaseUser, databasePassword, err = config.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, database.User, database.Password)
	}

	if err != nil {
		return err
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 || strings.TrimSpace(database.Host) == "" || strings.TrimSpace(database.Name) == "" {
		return errors.New("invalid database connection settings")
	}

	mode := cfg.Database.SSLMode
	if mode == "" {
		mode = "verify-full"
	}

	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return errors.New("invalid database sslmode")
	}

	if err := config.ValidateDatabaseTLS(database.Host, mode); err != nil {
		return err
	}

	address := &url.URL{Scheme: "postgres", User: url.UserPassword(databaseUser, databasePassword), Host: net.JoinHostPort(database.Host, strconv.Itoa(cfg.Database.Port)), Path: "/" + database.Name}
	query := address.Query()
	query.Set("sslmode", mode)
	address.RawQuery = query.Encode()

	db, err := sql.Open("postgres", address.String())
	if err != nil {
		return errors.New("open database failed")
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return errors.New("connect to database failed")
	}

	return Apply(ctx, db, files, service, sentinel)
}
