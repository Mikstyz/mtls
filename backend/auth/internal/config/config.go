package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	sharedconfig "mtls/shared/config"
)

type Config struct {
	Database  DatabaseSettings `toml:"database"`
	Services  Services         `toml:"services"`
	Security  Security         `toml:"security"`
	Resources Resources        `toml:"resources"`
	HTTP      HTTP             `toml:"http"`
	Redis     Redis            `toml:"redis"`
	Kafka     Kafka            `toml:"kafka"`
}

type Kafka struct {
	Brokers  []string `toml:"brokers"`
	Topic    string   `toml:"topic"`
	TLS      bool     `toml:"tls"`
	CAFile   string   `toml:"ca_file"`
	Username string   `toml:"username"`
	Password string   `toml:"password"`
}

type Redis struct {
	Address          string   `toml:"address"`
	Username         string   `toml:"username"`
	Password         string   `toml:"password"`
	TLS              bool     `toml:"tls"`
	CAFile           string   `toml:"ca_file"`
	SessionCache     bool     `toml:"session_cache"`
	SentinelMaster   string   `toml:"sentinel_master"`
	SentinelAddrs    []string `toml:"sentinel_addrs"`
	SentinelUsername string   `toml:"sentinel_username"`
	SentinelPassword string   `toml:"sentinel_password"`
}

type Security struct {
	InternalSecret           string `toml:"internal_secret"`
	AuthToUserSecret         string `toml:"auth_to_user_secret"`
	UserToAuthSecret         string `toml:"user_to_auth_secret"`
	PreviousUserToAuthSecret string `toml:"previous_user_to_auth_secret"`
	PreviousAuthToUserSecret string `toml:"previous_auth_to_user_secret"`
	RateLimitSecret          string `toml:"rate_limit_secret"`
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
	Auth Service `toml:"auth"`
}

type Service struct {
	Host         string                  `toml:"host"`
	Port         int                     `toml:"port"`
	RecoveryMode bool                    `toml:"recovery_mode"`
	Database     Database                `toml:"database"`
	User         UserService             `toml:"user"`
	Registration Registration            `toml:"registration"`
	Password     Password                `toml:"password"`
	TLS          sharedconfig.ServiceTLS `toml:"tls"`
}

type Password struct {
	BlocklistPath    string `toml:"blocklist_path"`
	NormalizeUnicode bool   `toml:"normalize_unicode"`
}

type Registration struct {
	DeliveryKey         string `toml:"delivery_key"`
	PreviousDeliveryKey string `toml:"previous_delivery_key"`
	SMTPHost            string `toml:"smtp_host"`
	SMTPCaFile          string `toml:"smtp_ca_file"`
	SMTPPort            int    `toml:"smtp_port"`
	SMTPUser            string `toml:"smtp_user"`
	SMTPPassword        string `toml:"smtp_password"`
	From                string `toml:"from"`
}

type UserService struct {
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

	if strings.TrimSpace(cfg.Services.Auth.Host) == "" {
		return fmt.Errorf("services.auth.host is required")
	}

	if cfg.Services.Auth.Port < 1 || cfg.Services.Auth.Port > 65535 {
		return fmt.Errorf("services.auth.port must be between 1 and 65535")
	}

	if cfg.Resources.MaxProcs < 0 || cfg.Resources.MemoryLimitBytes < 0 {
		return fmt.Errorf("services.auth.resources values cannot be negative")
	}

	if strings.TrimSpace(cfg.Services.Auth.Database.Host) == "" {
		return fmt.Errorf("services.auth.database.host is required")
	}

	if cfg.HTTP.AllowedOrigin != "" && strings.TrimSpace(cfg.Services.Auth.Password.BlocklistPath) == "" {
		origin, err := url.Parse(cfg.HTTP.AllowedOrigin)

		if err != nil || origin.Hostname() == "" {
			return fmt.Errorf("http.allowed_origin is invalid")
		}

		host := strings.ToLower(origin.Hostname())
		ip := net.ParseIP(host)

		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("services.auth.password.blocklist_path is required for a non-local origin")
		}
	}

	return nil
}
