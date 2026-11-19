package runconfig

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	sharedconfig "mtls/shared/config"
)

type Upload struct {
	Address         string                  `toml:"address"`
	Origin          string                  `toml:"origin"`
	CertFile        string                  `toml:"cert_file"`
	KeyFile         string                  `toml:"key_file"`
	CookieName      string                  `toml:"cookie_name"`
	UserURL         string                  `toml:"user_url"`
	UserSecret      string                  `toml:"user_secret"`
	UserTLS         sharedconfig.ServiceTLS `toml:"user_tls"`
	MaxFileBytes    int64                   `toml:"max_file_bytes"`
	MaxConcurrent   int                     `toml:"max_concurrent"`
	OwnerMaxAssets  int64                   `toml:"owner_max_assets"`
	OwnerMaxBytes   int64                   `toml:"owner_max_bytes"`
	GlobalMaxAssets int64                   `toml:"global_max_assets"`
	GlobalMaxBytes  int64                   `toml:"global_max_bytes"`
}

type Config struct {
	Database struct {
		Driver   string `toml:"driver"`
		Port     int    `toml:"port"`
		SSLMode  string `toml:"sslmode"`
		User     string `toml:"user"`
		Password string `toml:"password"`
	} `toml:"database"`
	Services struct {
		MediaProcessing struct {
			Database struct {
				Host     string  `toml:"host"`
				Name     string  `toml:"name"`
				User     string  `toml:"user"`
				Password *string `toml:"password"`
			} `toml:"database"`
			Upload     Upload `toml:"upload"`
			PhotoQueue struct {
				Quarantine string `toml:"quarantine"`
				Prepared   string `toml:"prepared"`
				Systemd    string `toml:"systemd_run"`
				Supervisor string `toml:"supervisor"`
				Bubblewrap string `toml:"bubblewrap"`
				Worker     string `toml:"worker"`
			} `toml:"photo_queue"`
		} `toml:"media_processing"`
	} `toml:"services"`
}

func StoragePaths(private, prepared string) (string, string, error) {
	paths := [2]string{private, prepared}
	var stats [2]os.FileInfo

	for i, path := range paths {
		if !filepath.IsAbs(path) {
			return "", "", errors.New("photo storage requires absolute paths")
		}

		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", "", err
		}

		info, err := os.Stat(resolved)
		if err != nil {
			return "", "", err
		}

		paths[i], stats[i] = resolved, info
	}

	if os.SameFile(stats[0], stats[1]) || containsPath(paths[0], paths[1]) || containsPath(paths[1], paths[0]) {
		return "", "", errors.New("quarantine and prepared storage must be separate directories")
	}

	return paths[0], paths[1], nil
}

func containsPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (cfg Config) OpenDatabase(ctx context.Context) (*sql.DB, error) {
	common, service := cfg.Database, cfg.Services.MediaProcessing.Database
	if common.Driver != "postgres" || common.Port < 1 || common.Port > 65535 || service.Host == "" || service.Name == "" {
		return nil, errors.New("invalid media processing database configuration")
	}

	mode := common.SSLMode
	if mode == "" {
		mode = "verify-full"
	}
	switch mode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return nil, errors.New("invalid database TLS mode")
	}

	if err := sharedconfig.ValidateDatabaseTLS(service.Host, mode); err != nil {
		return nil, err
	}

	user, password, err := sharedconfig.ResolveDatabaseCredentials(common.User, common.Password, service.User, service.Password)
	if err != nil {
		return nil, err
	}

	address := url.URL{
		Scheme:   "postgres",
		Host:     net.JoinHostPort(service.Host, strconv.Itoa(common.Port)),
		User:     url.UserPassword(user, password),
		Path:     "/" + service.Name,
		RawQuery: url.Values{"sslmode": {mode}}.Encode(),
	}
	db, err := sql.Open("postgres", address.String())
	if err != nil {
		return nil, errors.New("invalid media processing database connection")
	}

	db.SetMaxOpenConns(2)
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(probe); err != nil {
		db.Close()
		return nil, errors.New("media processing database unavailable")
	}

	return db, nil
}
