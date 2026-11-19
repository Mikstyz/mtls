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
	"strings"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

var errUnauthorized = errors.New("session unauthorized")

type userClient struct {
	url        string
	cookieName string
	client     *http.Client
}

func newUserClient(address, cookieName string) (*userClient, error) {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid user service URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	if ip == nil || !ip.IsLoopback() || (cookieName != "mtls_session" && cookieName != "__Host-mtls_session") {
		return nil, errors.New("invalid user service settings")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
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
	cookies := request.CookiesNamed(u.cookieName)

	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		return uuid.Nil, errUnauthorized
	}

	for _, b := range []byte(cookies[0].Value) {
		if !(b >= 'a' && b <= 'z') && !(b >= 'A' && b <= 'Z') && !(b >= '0' && b <= '9') && b != '-' && b != '_' {
			return uuid.Nil, errUnauthorized
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+"/api/users/me", nil)

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
	cookie, err := request.Cookie(u.cookieName)
	if err != nil {
		return "", errUnauthorized
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+"/api/users/media/"+id.String()+"/ownership", nil)
	if err != nil {
		return "", err
	}

	req.AddCookie(cookie)
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return resp.Header.Get("X-Media-Kind"), nil
	case http.StatusUnauthorized:
		return "", errUnauthorized
	case http.StatusNotFound:
		return "", errMediaUnavailable
	default:
		return "", errors.New("user service unavailable")
	}
}
