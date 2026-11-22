package config

import (
	"fmt"
	"net"
	"strings"

	sharedconfig "mtls/shared/config"
)

type Config struct {
	Database  DatabaseSettings `toml:"database"`
	Services  Services         `toml:"services"`
	Resources Resources        `toml:"resources"`
}

type DatabaseSettings struct {
	Driver       string `toml:"driver"`
	Port         int    `toml:"port"`
	SSLMode      string `toml:"sslmode"`
	User         string `toml:"user"`
	Password     string `toml:"password"`
	MaxOpenConns int    `toml:"max_open_conns"`
	MaxIdleConns int    `toml:"max_idle_conns"`
}

type Services struct {
	Content Service `toml:"content"`
}

type Service struct {
	TestSales              bool          `toml:"test_sales"`
	Host                   string        `toml:"host"`
	Port                   int           `toml:"port"`
	InternalSecret         string        `toml:"internal_secret"`
	MediaViewSecret        string        `toml:"media_view_secret"`
	ProfilePointsSecret    string        `toml:"profile_points_secret"`
	MediaRevocationSecret  string        `toml:"media_revocation_secret"`
	PurgeSecret            string        `toml:"purge_secret"`
	PreviousPurgeSecret    string        `toml:"purge_secret_previous"`
	PreviousInternalSecret string        `toml:"internal_secret_previous"`
	MaxConnections         int           `toml:"max_connections"`
	RecoveryMode           bool          `toml:"recovery_mode"`
	Database               Database      `toml:"database"`
	User                   UserService   `toml:"user"`
	Search                 SearchService `toml:"search"`
	Media                  MediaService  `toml:"media"`
}

type MediaService struct {
	URL    string `toml:"url"`
	Secret string `toml:"internal_secret"`
}

type SearchService struct {
	URL              string  `toml:"url"`
	WriterSecret     string  `toml:"writer_secret"`
	DatabaseUser     string  `toml:"database_user"`
	DatabasePassword *string `toml:"database_password"`
}

type UserService struct {
	URL               string                  `toml:"url"`
	CookieName        string                  `toml:"cookie_name"`
	PublicationSecret string                  `toml:"publication_secret"`
	TLS               sharedconfig.ServiceTLS `toml:"tls"`
}

type Database struct {
	Host          string  `toml:"host"`
	Name          string  `toml:"name"`
	User          string  `toml:"user"`
	Password      *string `toml:"password"`
	PurgeUser     string  `toml:"purge_user"`
	PurgePassword *string `toml:"purge_password"`
}

type Resources struct {
	MaxProcs         int   `toml:"max_procs"`
	MemoryLimitBytes int64 `toml:"memory_limit_bytes"`
}

func Load(path string) (Config, error) {
	var cfg Config

	if err := sharedconfig.Load(path, &cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (cfg Config) Validate() error {
	ip := net.ParseIP(cfg.Services.Content.Host)

	if ip == nil || !ip.IsLoopback() || cfg.Services.Content.Port < 1 || cfg.Services.Content.Port > 65535 {
		return fmt.Errorf("content requires a loopback IP and valid port")
	}

	if cfg.Database.Driver != "postgres" || cfg.Database.Port < 1 || cfg.Database.Port > 65535 || strings.TrimSpace(cfg.Services.Content.Database.Host) == "" || strings.TrimSpace(cfg.Services.Content.Database.Name) == "" {
		return fmt.Errorf("content requires a PostgreSQL database")
	}

	if cfg.Database.MaxOpenConns < 0 || cfg.Database.MaxIdleConns < 0 || cfg.Services.Content.MaxConnections < 0 || cfg.Services.Content.MaxConnections > 4096 || cfg.Resources.MaxProcs < 0 || cfg.Resources.MemoryLimitBytes < 0 {
		return fmt.Errorf("invalid content resource settings")
	}

	mode := cfg.Database.SSLMode

	if mode == "" {
		mode = "verify-full"
	}

	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("invalid database sslmode")
	}

	if err := sharedconfig.ValidateDatabaseTLS(cfg.Services.Content.Database.Host, mode); err != nil {
		return err
	}

	_, _, err := sharedconfig.ResolveDatabaseCredentials(cfg.Database.User, cfg.Database.Password, cfg.Services.Content.Database.User, cfg.Services.Content.Database.Password)
	return err
}
