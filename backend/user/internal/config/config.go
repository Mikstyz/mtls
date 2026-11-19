package config

import (
	"fmt"
	"strings"

	sharedconfig "mtls/shared/config"
)

type Config struct {
	Database  DatabaseSettings `toml:"database"`
	Services  Services         `toml:"services"`
	Security  Security         `toml:"security"`
	Resources Resources        `toml:"resources"`
	HTTP      HTTP             `toml:"http"`
}

type Security struct {
	InternalSecret           string `toml:"internal_secret"`
	AuthToUserSecret         string `toml:"auth_to_user_secret"`
	UserToAuthSecret         string `toml:"user_to_auth_secret"`
	PreviousAuthToUserSecret string `toml:"previous_auth_to_user_secret"`
	PreviousUserToAuthSecret string `toml:"previous_user_to_auth_secret"`
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
	User    Service       `toml:"user"`
	Search  SharedSearch  `toml:"search"`
	Content SharedContent `toml:"content"`
}

type SharedContent struct {
	InternalSecret string `toml:"internal_secret"`
	PurgeSecret    string `toml:"purge_secret"`
}

type SharedSearch struct {
	ReaderSecret string `toml:"reader_secret"`
	WriterSecret string `toml:"writer_secret"`
}

type Service struct {
	Host         string                  `toml:"host"`
	Port         int                     `toml:"port"`
	RecoveryMode bool                    `toml:"recovery_mode"`
	Database     Database                `toml:"database"`
	Auth         Auth                    `toml:"auth"`
	Search       Search                  `toml:"search"`
	Content      Content                 `toml:"content"`
	Media        MediaService            `toml:"media"`
	TLS          sharedconfig.ServiceTLS `toml:"tls"`
}

type MediaService struct {
	Secret         string `toml:"secret"`
	PreviousSecret string `toml:"previous_secret"`
	ClientURI      string `toml:"client_uri"`
}

type Content struct {
	URL          string `toml:"url"`
	PurgeSecret  string `toml:"purge_secret"`
	SearchSecret string `toml:"search_secret"`
}

type Search struct {
	URL          string `toml:"url"`
	ReaderSecret string `toml:"reader_secret"`
	WriterSecret string `toml:"writer_secret"`
}

type Auth struct {
	URL string `toml:"url"`
}

type HTTP struct {
	AllowedOrigin string `toml:"allowed_origin"`
	CookieSecure  bool   `toml:"cookie_secure"`
}

type Resources struct {
	MaxProcs         int   `toml:"max_procs"`
	MemoryLimitBytes int64 `toml:"memory_limit_bytes"`
}

type Database struct {
	Host     string  `toml:"host"`
	Name     string  `toml:"name"`
	User     string  `toml:"user"`
	Password *string `toml:"password"`
}

// Load reads only the settings needed by this service.
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

// Validate checks the settings required by this service.
func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.Database.Driver) == "" {
		return fmt.Errorf("database.driver is required")
	}

	if cfg.Database.MaxOpenConns < 0 || cfg.Database.MaxIdleConns < 0 {
		return fmt.Errorf("database connection pool values cannot be negative")
	}

	if cfg.Database.Port < 1 || cfg.Database.Port > 65535 {
		return fmt.Errorf("database.port must be between 1 and 65535")
	}

	if strings.TrimSpace(cfg.Services.User.Host) == "" {
		return fmt.Errorf("services.user.host is required")
	}

	if cfg.Services.User.Port < 1 || cfg.Services.User.Port > 65535 {
		return fmt.Errorf("services.user.port must be between 1 and 65535")
	}

	if cfg.Resources.MaxProcs < 0 || cfg.Resources.MemoryLimitBytes < 0 {
		return fmt.Errorf("services.user.resources values cannot be negative")
	}

	if strings.TrimSpace(cfg.Services.User.Database.Host) == "" {
		return fmt.Errorf("services.user.database.host is required")
	}

	return nil
}
