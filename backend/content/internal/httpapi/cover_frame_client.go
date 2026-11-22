package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type CoverFramePeer struct {
	URL    string
	Secret string
}

type coverFrameClient struct {
	baseURL string
	secret  string
	client  *http.Client
}

func newCoverFrameClient(peer CoverFramePeer) (*coverFrameClient, error) {
	if peer.URL == "" && peer.Secret == "" {
		return nil, nil
	}

	address, err := url.Parse(peer.URL)
	if err != nil || address.Scheme != "http" || !net.ParseIP(address.Hostname()).IsLoopback() ||
		address.User != nil || address.RawQuery != "" || address.ForceQuery || address.Fragment != "" ||
		(address.Path != "" && address.Path != "/") {
		return nil, errors.New("cover frames require a loopback media URL")
	}

	if len(peer.Secret) < 32 || len(peer.Secret) > 128 ||
		strings.ContainsFunc(peer.Secret, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return nil, errors.New("invalid media credential for cover frames")
	}

	return &coverFrameClient{
		baseURL: strings.TrimRight(address.String(), "/"),
		secret:  peer.Secret,
		client: &http.Client{
			Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext},
			Timeout:   4 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *coverFrameClient) check(ctx context.Context, cookie *http.Cookie, media uuid.UUID, frame string) error {
	if c == nil {
		return errors.New("cover frame media service is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.baseURL+"/internal/cover-frames/"+media.String()+"/"+frame, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Internal-Secret", c.secret)
	req.AddCookie(cookie)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if resp.Header.Get("Content-Type") == "image/jpeg" {
			return nil
		}
	case http.StatusNotFound:
		return errMediaUnavailable
	case http.StatusUnauthorized:
		return errUnauthorized
	case http.StatusForbidden:
		return errForbidden
	}
	return errors.New("cover frame media check unavailable")
}
