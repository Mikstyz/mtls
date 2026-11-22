// Package userclient authenticates uploads and registers their private ownership.
package userclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	sharedconfig "mtls/shared/config"
)

var (
	ErrInvalid         = errors.New("invalid user request")
	ErrUnauthenticated = errors.New("session is not authenticated")
	ErrForbidden       = errors.New("media owner is not authorized")
	ErrConflict        = errors.New("media ownership conflict")
	ErrUnavailable     = errors.New("user service unavailable")
)

type Client struct {
	base       string
	secret     string
	cookieName string
	http       *http.Client
}

// New requires verified mTLS for a non-loopback user service.
func New(address, secret, cookieName string, tls sharedconfig.ServiceTLS) (*Client, error) {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, ErrInvalid
	}

	if len(secret) < 32 || len(secret) > 128 || (cookieName != "mtls_session" && cookieName != "__Host-mtls_session") {
		return nil, ErrInvalid
	}

	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return nil, ErrInvalid
		}
	}

	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())

	if !loopback && (parsed.Scheme != "https" || tls.PeerCAFile == "" || tls.PeerCertFile == "" || tls.PeerKeyFile == "") {
		return nil, ErrInvalid
	}

	transport, err := tls.ClientTransport(address)

	if err != nil {
		return nil, ErrInvalid
	}

	return &Client{
		base:       strings.TrimRight(address, "/"),
		secret:     secret,
		cookieName: cookieName,
		http: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) cookie(token string) (*http.Cookie, error) {
	if token == "" || len(token) > 256 {
		return nil, ErrInvalid
	}

	cookie := &http.Cookie{Name: c.cookieName, Value: token}

	if err := cookie.Valid(); err != nil {
		return nil, ErrInvalid
	}

	return cookie, nil
}

// Identity resolves the current session through user and auth.
func (c *Client) Identity(ctx context.Context, token string) (uuid.UUID, error) {
	return c.identity(ctx, token, "/api/users/me")
}

func (c *Client) UploadIdentity(ctx context.Context, token string) (uuid.UUID, error) {
	return c.identity(ctx, token, "/api/users/me/participation")
}

func (c *Client) identity(ctx context.Context, token, path string) (uuid.UUID, error) {
	cookie, err := c.cookie(token)

	if err != nil || ctx == nil {
		return uuid.Nil, ErrInvalid
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)

	if err != nil {
		return uuid.Nil, ErrInvalid
	}

	req.AddCookie(cookie)
	resp, err := c.http.Do(req)

	if err != nil {
		return uuid.Nil, ErrUnavailable
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return uuid.Nil, ErrUnauthenticated
	}

	if resp.StatusCode == http.StatusForbidden {
		return uuid.Nil, ErrForbidden
	}

	if resp.StatusCode != http.StatusOK {
		return uuid.Nil, ErrUnavailable
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))

	if err != nil || len(data) > 4096 {
		return uuid.Nil, ErrUnavailable
	}

	var result struct {
		ID uuid.UUID `json:"id"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	if decoder.Decode(&result) != nil || result.ID == uuid.Nil || decoder.Decode(new(any)) != io.EOF {
		return uuid.Nil, ErrUnavailable
	}

	return result.ID, nil
}

// Reserve registers an existing processing reservation under the same live session.
func (c *Client) Reserve(ctx context.Context, token string, owner, media uuid.UUID) error {
	cookie, err := c.cookie(token)

	if err != nil || ctx == nil || owner == uuid.Nil || media == uuid.Nil {
		return ErrInvalid
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+"/internal/media/"+media.String()+"/reservation", nil)

	if err != nil {
		return ErrInvalid
	}

	req.Header.Set("X-Media-Service-Secret", c.secret)
	req.Header.Set("X-Media-Owner", owner.String())
	req.AddCookie(cookie)
	resp, err := c.http.Do(req)

	if err != nil {
		return ErrUnavailable
	}

	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthenticated
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusConflict:
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

// MarkReady reports a committed processing result using the service credential.
func (c *Client) MarkReady(ctx context.Context, owner, media uuid.UUID, kind string, duration *int64) error {
	if kind != "photo" && kind != "video" {
		return ErrInvalid
	}

	return c.updatePolicy(ctx, owner, media, "ready", kind, duration)
}

func (c *Client) Revoke(ctx context.Context, owner, media uuid.UUID) error {
	return c.updatePolicy(ctx, owner, media, "revoke", "", nil)
}

func (c *Client) updatePolicy(ctx context.Context, owner, media uuid.UUID, action, kind string, duration *int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+"/internal/media/"+media.String()+"/"+action, nil)
	if err != nil {
		return ErrInvalid
	}

	req.Header.Set("X-Media-Service-Secret", c.secret)
	req.Header.Set("X-Media-Owner", owner.String())
	if kind != "" {
		req.Header.Set("X-Media-Kind", kind)
	}
	if duration != nil {
		req.Header.Set("X-Media-Duration-Ms", strconv.FormatInt(*duration, 10))
	}
	resp, err := c.http.Do(req)

	if err != nil {
		return ErrUnavailable
	}

	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}

	return nil
}
