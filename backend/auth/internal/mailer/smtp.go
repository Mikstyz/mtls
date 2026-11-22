package mailer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	sharedconfig "mtls/shared/config"
)

type SMTP struct {
	CAFile   string
	roots    *x509.CertPool
	Host     string
	Port     int
	Username string
	Password string
	From     string
	Origin   string
}

func (s *SMTP) Validate() error {
	from, err := mail.ParseAddress(s.From)

	if err != nil || from.Address != s.From || strings.ContainsAny(s.From, "\r\n") {
		return errors.New("invalid SMTP sender")
	}

	if strings.TrimSpace(s.Host) == "" || s.Port < 1 || s.Port > 65535 || (s.Username == "") != (s.Password == "") {
		return errors.New("invalid SMTP configuration")
	}

	origin, err := url.Parse(s.Origin)

	if err != nil || origin == nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return errors.New("invalid confirmation origin")
	}

	if origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1")) {
		return errors.New("confirmation origin requires HTTPS")
	}

	if s.CAFile != "" && s.roots == nil {
		roots, err := sharedconfig.LoadCertPool(s.CAFile)

		if err != nil {
			return fmt.Errorf("load SMTP CA: %w", err)
		}

		s.roots = roots
	}

	return nil
}

// SendConfirmation requires STARTTLS and never writes a token to logs.
func (s SMTP) SendConfirmation(ctx context.Context, recipient, token string) error {
	return s.send(ctx, recipient, token, "/auth/verify", "Confirm your email")
}

func (s SMTP) SendPasswordReset(ctx context.Context, recipient, token string) error {
	return s.send(ctx, recipient, token, "/auth/reset-password", "Reset your password")
}

func (s SMTP) SendEmailVerification(ctx context.Context, recipient, token string) error {
	return s.send(ctx, recipient, token, "/auth/verify-email", "Verify your email")
}

func (s SMTP) SendEmailChange(ctx context.Context, recipient, token string) error {
	return s.send(ctx, recipient, token, "/auth/change-email", "Confirm your new email")
}

func (s SMTP) send(ctx context.Context, recipient, token, path, subject string) error {
	address, err := mail.ParseAddress(recipient)

	if err != nil || address.Address != recipient || strings.ContainsAny(recipient, "\r\n") || len(token) != 43 {
		return errors.New("invalid confirmation recipient or token")
	}

	if err := s.Validate(); err != nil {
		return err
	}

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))

	if err != nil {
		return fmt.Errorf("connect to SMTP: %w", err)
	}

	defer conn.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()

	deadline := time.Now().Add(20 * time.Second)

	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, s.Host)

	if err != nil {
		return fmt.Errorf("initialize SMTP: %w", err)
	}

	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("SMTP server does not support STARTTLS")
	}

	if err := client.StartTLS(&tls.Config{ServerName: s.Host, RootCAs: s.roots, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("start SMTP TLS: %w", err)
	}

	if s.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return errors.New("SMTP authentication failed")
		}
	}

	if err := client.Mail(s.From); err != nil {
		return errors.New("SMTP sender rejected")
	}

	if err := client.Rcpt(recipient); err != nil {
		return errors.New("SMTP recipient rejected")
	}

	writer, err := client.Data()

	if err != nil {
		return errors.New("SMTP message rejected")
	}

	link := s.Origin + path + "#token=" + url.QueryEscape(token)
	message := "From: " + s.From + "\r\nTo: " + recipient + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + subject + ":\r\n" + link + "\r\n"

	if _, err := writer.Write([]byte(message)); err != nil {
		return errors.New("SMTP message write failed")
	}

	if err := writer.Close(); err != nil {
		return errors.New("SMTP delivery failed")
	}

	return nil
}
