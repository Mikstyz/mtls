package contentcleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Publisher struct {
	db     *sql.DB
	base   string
	secret string
	client *http.Client
}

type event struct {
	userID uuid.UUID
	lease  uuid.UUID
}

func New(db *sql.DB, address, secret string) (*Publisher, error) {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid content cleanup URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	if db == nil || ip == nil || !ip.IsLoopback() || len(secret) < 32 || len(secret) > 128 {
		return nil, errors.New("invalid content cleanup settings")
	}

	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return nil, errors.New("invalid content cleanup settings")
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Publisher{
		db:     db,
		base:   strings.TrimRight(address, "/"),
		secret: secret,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (p *Publisher) claim(ctx context.Context) (*event, error) {
	tx, err := p.db.BeginTx(ctx, nil)

	if err != nil {
		return nil, fmt.Errorf("begin cleanup claim: %w", err)
	}

	defer tx.Rollback()

	var item event
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM content_purge_events
        WHERE lease_until IS NULL OR lease_until < clock_timestamp()
        ORDER BY created_at, user_id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&item.userID)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("claim cleanup event: %w", err)
	}

	item.lease, err = uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("create cleanup lease: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE content_purge_events SET lease_token=$2, lease_until=clock_timestamp()+interval '30 seconds' WHERE user_id=$1`, item.userID, item.lease); err != nil {
		return nil, fmt.Errorf("lease cleanup event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit cleanup claim: %w", err)
	}

	return &item, nil
}

func (p *Publisher) DeliverOne(ctx context.Context) (bool, error) {
	item, err := p.claim(ctx)

	if err != nil || item == nil {
		return false, err
	}

	var hasMedia bool
	if err := p.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM media_permissions WHERE owner_id=$1)`, item.userID).Scan(&hasMedia); err != nil {
		return true, fmt.Errorf("check pending media cleanup: %w", err)
	}

	if hasMedia {
		return true, errors.New("media cleanup is pending")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.base+"/internal/users/"+item.userID.String()+"/content", nil)

	if err != nil {
		return true, errors.New("create content cleanup request")
	}

	request.Header.Set("X-Internal-Secret", p.secret)
	response, err := p.client.Do(request)

	if err != nil {
		return true, errors.New("content cleanup unavailable")
	}

	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))

	if response.StatusCode == http.StatusAccepted {
		_, err := p.db.ExecContext(ctx, `UPDATE content_purge_events SET lease_token=NULL, lease_until=clock_timestamp()+interval '1 second' WHERE user_id=$1 AND lease_token=$2`, item.userID, item.lease)
		if err != nil {
			return true, fmt.Errorf("schedule next cleanup batch: %w", err)
		}
		return true, nil
	}

	if response.StatusCode != http.StatusNoContent {
		return true, errors.New("content cleanup rejected")
	}

	if _, err := p.db.ExecContext(ctx, `DELETE FROM content_purge_events WHERE user_id=$1 AND lease_token=$2`, item.userID, item.lease); err != nil {
		return true, fmt.Errorf("acknowledge content cleanup: %w", err)
	}

	return true, nil
}
