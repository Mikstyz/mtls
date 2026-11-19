// Package searchindex delivers committed public content changes to search.
package searchindex

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	version int64
	postID  uuid.UUID
	title   string
	deleted bool
	lease   uuid.UUID
}

func New(db *sql.DB, address, secret string) (*Publisher, error) {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid search service URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	if db == nil || ip == nil || !ip.IsLoopback() || len(secret) < 32 || len(secret) > 128 {
		return nil, errors.New("invalid search publisher settings")
	}

	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return nil, errors.New("invalid search publisher settings")
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	return &Publisher{
		db:     db,
		base:   strings.TrimRight(address, "/"),
		secret: secret,
		client: &http.Client{
			Transport:     transport,
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (p *Publisher) claim(ctx context.Context) (*event, error) {
	tx, err := p.db.BeginTx(ctx, nil)

	if err != nil {
		return nil, fmt.Errorf("begin search event claim: %w", err)
	}

	defer tx.Rollback()

	const selectEvent = `SELECT version, post_id, title, deleted FROM content_search_events
		WHERE lease_until IS NULL OR lease_until < clock_timestamp()
		ORDER BY version FOR UPDATE SKIP LOCKED LIMIT 1`

	var item event
	err = tx.QueryRowContext(ctx, selectEvent).Scan(&item.version, &item.postID, &item.title, &item.deleted)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("claim search event: %w", err)
	}

	item.lease, err = uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("create search event lease: %w", err)
	}

	const leaseEvent = `UPDATE content_search_events SET lease_token=$2,
		lease_until=clock_timestamp()+interval '30 seconds' WHERE version=$1`

	if _, err := tx.ExecContext(ctx, leaseEvent, item.version, item.lease); err != nil {
		return nil, fmt.Errorf("lease search event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit search event claim: %w", err)
	}

	return &item, nil
}

func (p *Publisher) DeliverOne(ctx context.Context) (bool, error) {
	item, err := p.claim(ctx)

	if err != nil || item == nil {
		return false, err
	}

	body, err := json.Marshal(struct {
		Version int64  `json:"version"`
		Text    string `json:"text"`
		Deleted bool   `json:"deleted"`
	}{item.version, item.title, item.deleted})

	if err != nil {
		return true, errors.New("encode search event")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, p.base+"/internal/documents/content/"+item.postID.String(), bytes.NewReader(body))

	if err != nil {
		return true, errors.New("create search event request")
	}

	request.Header.Set("X-Internal-Secret", p.secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)

	if err != nil {
		return true, errors.New("search event delivery unavailable")
	}

	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))

	if response.StatusCode != http.StatusNoContent {
		return true, errors.New("search event delivery rejected")
	}

	const acknowledge = `DELETE FROM content_search_events WHERE version=$1 AND lease_token=$2`

	if _, err := p.db.ExecContext(ctx, acknowledge, item.version, item.lease); err != nil {
		return true, fmt.Errorf("acknowledge search event: %w", err)
	}

	return true, nil
}
