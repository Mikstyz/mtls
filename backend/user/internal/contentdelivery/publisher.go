package contentdelivery

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Publisher struct {
	db     *sql.DB
	url    string
	secret string
	client *http.Client
	claim  string
	ack    string
	label  string
}

func NewProfilePoints(db *sql.DB, address, secret string) (*Publisher, error) {
	const claim = `SELECT id::text,jsonb_build_object('case_id',case_id,'owner_id',owner_id,'operation',operation,'reason',reason),lease_token
		FROM public.user_claim_profile_points_event()`
	const ack = `SELECT public.user_ack_profile_points_event($1::bigint,$2)`
	return newPublisher(db, address, secret, "/internal/profile-moderation/points", "profile points", claim, ack)
}

func NewMediaRevocations(db *sql.DB, address, secret string) (*Publisher, error) {
	const claim = `SELECT media_id::text,jsonb_build_object('media_id',media_id,'owner_id',owner_id),lease_token
		FROM public.user_claim_media_revocation()`
	const ack = `SELECT public.user_ack_media_revocation($1::uuid,$2)`
	return newPublisher(db, address, secret, "/internal/media-revocations", "media revocation", claim, ack)
}

func newPublisher(db *sql.DB, address, secret, path, label, claim, ack string) (*Publisher, error) {
	target, err := url.Parse(address)
	if err != nil || target.Scheme != "http" || !net.ParseIP(target.Hostname()).IsLoopback() ||
		target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" ||
		(target.Path != "" && target.Path != "/") {
		return nil, errors.New("delivery requires a loopback content URL")
	}

	if db == nil || len(secret) < 32 || len(secret) > 128 ||
		strings.ContainsFunc(secret, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return nil, errors.New("invalid content delivery settings")
	}

	return &Publisher{
		db:     db,
		url:    strings.TrimRight(target.String(), "/") + path,
		secret: secret,
		claim:  claim,
		ack:    ack,
		label:  label,
		client: &http.Client{
			Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext},
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (p *Publisher) DeliverOne(ctx context.Context) (bool, error) {
	var id string
	var lease uuid.UUID
	var body []byte

	err := p.db.QueryRowContext(ctx, p.claim).Scan(&id, &body, &lease)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", p.secret)

	resp, err := p.client.Do(req)
	if err != nil {
		return true, errors.New("content unavailable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusNoContent {
		return true, fmt.Errorf("content rejected event: %d", resp.StatusCode)
	}

	if _, err := p.db.ExecContext(ctx, p.ack, id, lease); err != nil {
		return true, fmt.Errorf("acknowledge event: %w", err)
	}

	return true, nil
}

func (p *Publisher) Run(ctx context.Context) {
	defer p.client.CloseIdleConnections()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < 25; i++ {
				delivery, cancel := context.WithTimeout(ctx, 8*time.Second)
				found, err := p.DeliverOne(delivery)
				cancel()
				if err != nil && ctx.Err() == nil {
					log.Printf("%s delivery: %v", p.label, err)
				}
				if err != nil || !found {
					break
				}
			}
		}
	}
}
