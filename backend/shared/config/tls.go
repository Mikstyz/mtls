package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type ServiceTLS struct {
	CertFile     string `toml:"cert_file"`
	KeyFile      string `toml:"key_file"`
	ClientCAFile string `toml:"client_ca_file"`
	ClientURI    string `toml:"client_uri"`
	PeerCAFile   string `toml:"peer_ca_file"`
	PeerCertFile string `toml:"peer_cert_file"`
	PeerKeyFile  string `toml:"peer_key_file"`
}

// ServerConfig allows public requests without a client certificate; internal
// handlers separately require a verified certificate when a client CA is set.
func (cfg ServiceTLS) ServerConfig() (*tls.Config, bool, error) {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, false, errors.New("both TLS certificate and private key are required")
	}

	server := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.ClientCAFile == "" {
		if cfg.ClientURI != "" {
			return nil, false, errors.New("client URI requires a client CA")
		}

		return server, false, nil
	}

	if cfg.CertFile == "" {
		return nil, false, errors.New("client certificate verification requires server TLS")
	}

	identity, err := url.Parse(cfg.ClientURI)

	if err != nil || identity == nil || identity.Scheme != "spiffe" || identity.Hostname() == "" || identity.Port() != "" || identity.Path == "" || identity.Path == "/" || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" || identity.Opaque != "" {
		return nil, false, errors.New("a valid expected SPIFFE client URI is required")
	}

	pool, err := LoadCertPool(cfg.ClientCAFile)

	if err != nil {
		return nil, false, fmt.Errorf("load client CA: %w", err)
	}

	server.ClientAuth = tls.VerifyClientCertIfGiven
	server.ClientCAs = pool

	return server, true, nil
}

// MatchesClientURI checks the verified leaf certificate's URI SAN exactly.
func MatchesClientURI(state *tls.ConnectionState, expected string) bool {
	if state == nil || expected == "" {
		return false
	}

	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 {
			continue
		}

		for _, identity := range chain[0].URIs {
			if identity.String() == expected {
				return true
			}
		}
	}

	return false
}

func (cfg ServiceTLS) ClientTransport(peerURL string) (*http.Transport, error) {
	if (cfg.PeerCertFile == "") != (cfg.PeerKeyFile == "") {
		return nil, errors.New("both peer client certificate and private key are required")
	}

	peer, err := url.Parse(peerURL)

	if err != nil || peer == nil {
		return nil, errors.New("invalid peer URL")
	}

	if (cfg.PeerCAFile != "" || cfg.PeerCertFile != "") && peer.Scheme != "https" {
		return nil, errors.New("peer TLS settings require an HTTPS peer URL")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.PeerCAFile != "" {
		pool, err := LoadCertPool(cfg.PeerCAFile)

		if err != nil {
			return nil, fmt.Errorf("load peer CA: %w", err)
		}

		tlsConfig.RootCAs = pool
	}

	if cfg.PeerCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.PeerCertFile, cfg.PeerKeyFile)

		if err != nil {
			return nil, fmt.Errorf("load peer client certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
	}

	return transport, nil
}

// LoadCertPool loads a bounded PEM file containing trusted certificate authorities.
func LoadCertPool(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	info, err := file.Stat()

	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("CA must be a regular file no larger than 1 MiB")
	}

	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))

	if err != nil {
		return nil, err
	}

	if len(data) > 1<<20 {
		return nil, errors.New("CA exceeds 1 MiB")
	}

	pool := x509.NewCertPool()

	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file contains no valid certificates")
	}

	return pool, nil
}
