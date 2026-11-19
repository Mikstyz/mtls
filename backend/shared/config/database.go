package config

import (
	"errors"
	"net"
	"strings"
)

// ValidateDatabaseTLS permits weaker PostgreSQL TLS modes only on loopback.
func ValidateDatabaseTLS(host, sslMode string) error {
	if sslMode == "verify-full" {
		return nil
	}

	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	ip := net.ParseIP(host)

	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}

	return errors.New("remote database requires sslmode=verify-full")
}

// ResolveDatabaseCredentials uses the shared pair unless a complete service pair is set.
func ResolveDatabaseCredentials(commonUser, commonPassword, serviceUser string, servicePassword *string) (string, string, error) {
	if serviceUser == "" && servicePassword == nil {
		if strings.TrimSpace(commonUser) == "" {
			return "", "", errors.New("database user is required")
		}

		return commonUser, commonPassword, nil
	}

	if strings.TrimSpace(serviceUser) == "" || servicePassword == nil {
		return "", "", errors.New("service database user and password must be configured together")
	}

	return serviceUser, *servicePassword, nil
}
