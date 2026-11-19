package config

import (
	"errors"
	"net"
	"net/url"
)

// ResolveInternalSecrets returns separate auth-to-user and user-to-auth credentials.
// A shared legacy secret is allowed only when the peer uses loopback.
func ResolveInternalSecrets(peerURL, legacy, authToUser, userToAuth string) (string, string, error) {
	peer, err := url.Parse(peerURL)

	if err != nil || peer == nil || peer.Hostname() == "" {
		return "", "", errors.New("invalid service URL")
	}

	host := peer.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())

	if authToUser == "" && userToAuth == "" && loopback {
		authToUser = legacy
		userToAuth = legacy
	}

	if len(authToUser) < 32 || len(userToAuth) < 32 {
		return "", "", errors.New("both service credentials must be at least 32 bytes")
	}

	if !loopback && authToUser == userToAuth {
		return "", "", errors.New("remote services require separate credentials for each direction")
	}

	return authToUser, userToAuth, nil
}

// RequireMutualTLSForRemote prevents remote peers from silently using only a shared secret.
func RequireMutualTLSForRemote(peerURL string, cfg ServiceTLS) error {
	peer, err := url.Parse(peerURL)

	if err != nil || peer == nil || peer.Hostname() == "" {
		return errors.New("invalid service URL")
	}

	host := peer.Hostname()
	ip := net.ParseIP(host)

	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}

	if peer.Scheme != "https" || cfg.ClientCAFile == "" || cfg.ClientURI == "" || cfg.PeerCertFile == "" || cfg.PeerKeyFile == "" {
		return errors.New("remote peer requires mutual TLS with client identities")
	}

	return nil
}

// ValidateRateLimitSecret keeps rate-limit identifiers stable across key rotation.
func ValidateRateLimitSecret(peerURL, secret, authToUser, userToAuth string) error {
	peer, err := url.Parse(peerURL)

	if err != nil || peer == nil || peer.Hostname() == "" {
		return errors.New("invalid service URL")
	}

	host := peer.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())

	if secret == "" && loopback {
		return nil
	}

	if len(secret) < 32 || secret == authToUser || secret == userToAuth {
		return errors.New("an independent rate-limit secret of at least 32 bytes is required")
	}

	return nil
}

func ValidateInternalSecretRotation(authToUser, userToAuth, previousAuthToUser, previousUserToAuth string) error {
	for _, previous := range []string{previousAuthToUser, previousUserToAuth} {
		if previous != "" && (len(previous) < 32 || previous == authToUser || previous == userToAuth) {
			return errors.New("previous service credentials must be distinct and at least 32 bytes")
		}
	}

	if previousAuthToUser != "" && previousAuthToUser == previousUserToAuth {
		return errors.New("previous service credentials must differ by direction")
	}

	return nil
}
