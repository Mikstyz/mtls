package httpapi

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
	"mtls/content/internal/catalog"
	sharedconfig "mtls/shared/config"
)

var errForbidden = errors.New("operation forbidden")

var errUnauthorized = errors.New("session unauthorized")

type userClient struct {
	url        string
	cookieName string
	client     *http.Client
}

func newUserClient(address, cookieName string, settings sharedconfig.ServiceTLS) (*userClient, error) {
	parsed, err := url.Parse(address)

	if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("invalid user service URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	local := parsed.Scheme == "http" && ip != nil && ip.IsLoopback()
	mutualTLS := parsed.Scheme == "https" && settings.PeerCAFile != "" && settings.PeerCertFile != "" && settings.PeerKeyFile != ""
	if (!local && !mutualTLS) || (cookieName != "mtls_session" && cookieName != "__Host-mtls_session") {
		return nil, errors.New("invalid user service settings")
	}

	transport, err := settings.ClientTransport(address)
	if err != nil {
		return nil, err
	}
	return &userClient{
		url:        strings.TrimRight(address, "/"),
		cookieName: cookieName,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (u *userClient) author(ctx context.Context, request *http.Request) (uuid.UUID, error) {
	return u.sessionUser(ctx, request, "/api/users/me/participation")
}

func (u *userClient) sessionUser(ctx context.Context, request *http.Request, path string) (uuid.UUID, error) {
	cookies := request.CookiesNamed(u.cookieName)

	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		return uuid.Nil, errUnauthorized
	}

	for _, b := range []byte(cookies[0].Value) {
		if !(b >= 'a' && b <= 'z') && !(b >= 'A' && b <= 'Z') && !(b >= '0' && b <= '9') && b != '-' && b != '_' {
			return uuid.Nil, errUnauthorized
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+path, nil)

	if err != nil {
		return uuid.Nil, errors.New("user service unavailable")
	}

	req.AddCookie(&http.Cookie{Name: u.cookieName, Value: cookies[0].Value})
	response, err := u.client.Do(req)

	if err != nil {
		return uuid.Nil, errors.New("user service unavailable")
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return uuid.Nil, errUnauthorized
	}

	if response.StatusCode == http.StatusForbidden {
		return uuid.Nil, errForbidden
	}

	if response.StatusCode != http.StatusOK {
		return uuid.Nil, errors.New("user service unavailable")
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))

	if err != nil || len(body) > 4096 {
		return uuid.Nil, errors.New("invalid user response")
	}

	var result struct {
		ID uuid.UUID `json:"id"`
	}

	decoder := json.NewDecoder(bytes.NewReader(body))

	if decoder.Decode(&result) != nil || result.ID == uuid.Nil || decoder.Decode(new(any)) != io.EOF {
		return uuid.Nil, errors.New("invalid user response")
	}

	return result.ID, nil
}

var errMediaUnavailable = errors.New("media is not ready for this owner")

func (u *userClient) checkAuthorAccess(ctx context.Context, request *http.Request, author uuid.UUID) error {
	cookie, err := request.Cookie(u.cookieName)

	if err != nil {
		return errUnauthorized
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+"/api/users/"+author.String()+"/access", nil)

	if err != nil {
		return err
	}
	req.AddCookie(cookie)

	resp, err := u.client.Do(req)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return errUnauthorized
	case http.StatusNotFound:
		return catalog.ErrPostNotFound
	default:
		return errors.New("user service unavailable")
	}
}

// checkMediaOwner is used after author has validated the session cookie.
func (u *userClient) checkMediaOwner(ctx context.Context, request *http.Request, id uuid.UUID) error {
	_, err := u.ownedMediaKind(ctx, request, id)
	return err
}

func (u *userClient) ownedMediaKind(ctx context.Context, request *http.Request, id uuid.UUID) (string, error) {
	kind, _, err := u.ownedMedia(ctx, request, id)
	return kind, err
}

func (u *userClient) ownedMedia(ctx context.Context, request *http.Request, id uuid.UUID) (string, *int64, error) {
	cookie, err := request.Cookie(u.cookieName)
	if err != nil {
		return "", nil, errUnauthorized
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+"/api/users/media/"+id.String()+"/ownership", nil)
	if err != nil {
		return "", nil, err
	}

	req.AddCookie(cookie)
	resp, err := u.client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		kind := resp.Header.Get("X-Media-Kind")
		duration, err := readMediaDuration(resp.Header, kind)
		return kind, duration, err
	case http.StatusUnauthorized:
		return "", nil, errUnauthorized
	case http.StatusNotFound:
		return "", nil, errMediaUnavailable
	default:
		return "", nil, errors.New("user service unavailable")
	}
}

func readMediaDuration(headers http.Header, kind string) (*int64, error) {
	values := headers.Values("X-Media-Duration-Ms")
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 || kind != "video" {
		return nil, errors.New("invalid media duration")
	}
	duration, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || duration < 1 || duration > 86400000 {
		return nil, errors.New("invalid media duration")
	}
	return &duration, nil
}
