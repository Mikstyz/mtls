package redisshield

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Address          string   `toml:"address"`
	Username         string   `toml:"username"`
	Password         string   `toml:"password"`
	TLS              bool     `toml:"tls"`
	CAFile           string   `toml:"ca_file"`
	SentinelMaster   string   `toml:"sentinel_master"`
	SentinelAddrs    []string `toml:"sentinel_addrs"`
	SentinelUsername string   `toml:"sentinel_username"`
	SentinelPassword string   `toml:"sentinel_password"`
}

// Open validates the connection policy without making Redis a startup dependency.
func Open(cfg Config) (*Guard, error) {
	sentinel := cfg.SentinelMaster != "" || len(cfg.SentinelAddrs) != 0

	if cfg.Address == "" && !sentinel {
		if cfg.Username != "" || cfg.Password != "" || cfg.TLS || cfg.CAFile != "" || cfg.SentinelUsername != "" || cfg.SentinelPassword != "" {
			return nil, errors.New("redis address or sentinel settings are required")
		}

		return nil, nil
	}

	if (cfg.Username == "") != (cfg.Password == "") || (cfg.SentinelUsername == "") != (cfg.SentinelPassword == "") {
		return nil, errors.New("redis and sentinel usernames and passwords must be configured together")
	}

	if !cfg.TLS && cfg.CAFile != "" {
		return nil, errors.New("redis CA requires TLS")
	}

	var tlsConfig *tls.Config

	if cfg.TLS {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		if cfg.CAFile != "" {
			pool, err := loadCA(cfg.CAFile)

			if err != nil {
				return nil, err
			}

			tlsConfig.RootCAs = pool
		}
	}

	if sentinel {
		if cfg.Address != "" || cfg.SentinelMaster == "" || strings.TrimSpace(cfg.SentinelMaster) != cfg.SentinelMaster || len(cfg.SentinelMaster) > 128 || len(cfg.SentinelAddrs) == 0 || len(cfg.SentinelAddrs) > 16 {
			return nil, errors.New("invalid redis sentinel configuration")
		}

		for _, address := range cfg.SentinelAddrs {
			local, err := localAddress(address)

			if err != nil {
				return nil, err
			}

			if !local && (!cfg.TLS || cfg.Username == "" || cfg.SentinelUsername == "") {
				return nil, errors.New("remote redis sentinel requires TLS and separate ACL credentials")
			}
		}

		dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()

			local, err := localAddress(address)

			if err != nil {
				return nil, err
			}

			// Sentinel supplies primary and peer addresses dynamically; apply the
			// same transport policy to those addresses as to the configured seeds.
			if !local && (!cfg.TLS || cfg.Username == "" || cfg.SentinelUsername == "") {
				return nil, errors.New("remote redis sentinel target requires TLS and ACL credentials")
			}

			if tlsConfig != nil {
				return (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, network, address)
			}

			return dialer.DialContext(ctx, network, address)
		}

		options := &redis.FailoverOptions{
			MasterName:            cfg.SentinelMaster,
			SentinelAddrs:         append([]string(nil), cfg.SentinelAddrs...),
			Username:              cfg.Username,
			Password:              cfg.Password,
			SentinelUsername:      cfg.SentinelUsername,
			SentinelPassword:      cfg.SentinelPassword,
			Dialer:                dial,
			TLSConfig:             tlsConfig,
			Protocol:              2,
			MaxRetries:            -1,
			PoolSize:              8,
			MaxActiveConns:        16,
			DialTimeout:           200 * time.Millisecond,
			ReadTimeout:           250 * time.Millisecond,
			WriteTimeout:          250 * time.Millisecond,
			PoolTimeout:           250 * time.Millisecond,
			ContextTimeoutEnabled: true,
			DisableIdentity:       true,
		}

		return New(redis.NewFailoverClient(options)), nil
	}

	if cfg.SentinelUsername != "" || cfg.SentinelPassword != "" {
		return nil, errors.New("sentinel credentials require sentinel configuration")
	}

	local, err := localAddress(cfg.Address)

	if err != nil {
		return nil, err
	}

	if !local && (!cfg.TLS || cfg.Username == "") {
		return nil, errors.New("remote redis requires TLS and ACL credentials")
	}

	options := &redis.Options{
		Addr: cfg.Address, Username: cfg.Username, Password: cfg.Password,
		Protocol: 2, MaxRetries: -1, PoolSize: 8, MaxActiveConns: 16,
		DialTimeout: 200 * time.Millisecond, ReadTimeout: 250 * time.Millisecond,
		WriteTimeout: 250 * time.Millisecond, PoolTimeout: 250 * time.Millisecond,
		ContextTimeoutEnabled: true, DisableIdentity: true, TLSConfig: tlsConfig,
	}

	return New(redis.NewClient(options)), nil
}

func localAddress(address string) (bool, error) {
	host, port, err := net.SplitHostPort(address)

	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host || len(host) > 253 {
		return false, errors.New("invalid redis address")
	}

	portNumber, err := strconv.Atoi(port)

	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false, errors.New("invalid redis port")
	}

	ip := net.ParseIP(host)

	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()), nil
}

func loadCA(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("open redis CA: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))

	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("cannot read redis CA")
	}

	pool := x509.NewCertPool()

	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid redis CA")
	}

	return pool, nil
}

func (g *Guard) Close() error {
	return g.client.Close()
}
