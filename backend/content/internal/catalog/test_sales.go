package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrSalesDisabled = errors.New("test sales disabled")
var ErrOfferConflict = errors.New("test offer conflict")

type TestOffer struct {
	Author   uuid.UUID `json:"author_id"`
	Revision int64     `json:"revision"`
	Amount   int64     `json:"amount_minor"`
	Currency string    `json:"currency"`
}

func NewWithTestSales(db *sql.DB) *Store { return &Store{db: db, testSales: true} }

func (s *Store) TestOffer(ctx context.Context, id uuid.UUID) (TestOffer, error) {
	var offer TestOffer
	if !s.testSales {
		return offer, ErrSalesDisabled
	}
	const query = `SELECT p.author_id,o.revision,o.amount_minor,o.currency
 FROM content_posts p JOIN content_test_offers o ON o.post_id=p.id AND o.revision=COALESCE(p.published_edition,p.revision)
 WHERE p.id=$1 AND p.status='published' AND p.hidden_by_case IS NULL AND p.visibility='private'
 AND NOT EXISTS(SELECT 1 FROM content_author_purges WHERE author_id=p.author_id)`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&offer.Author, &offer.Revision, &offer.Amount, &offer.Currency)
	if errors.Is(err, sql.ErrNoRows) {
		return offer, ErrPostNotFound
	}
	return offer, err
}

func (s *Store) CreateTestOffer(ctx context.Context, id, author uuid.UUID, offer TestOffer) error {
	if !s.testSales {
		return ErrSalesDisabled
	}
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_test_offer($1,$2,$3,$4,$5)`, id, author, offer.Revision, offer.Amount, offer.Currency).Scan(&ok)
	if err == nil && !ok {
		return ErrOfferConflict
	}
	return err
}

func (s *Store) BuyTestOffer(ctx context.Context, id, buyer, request uuid.UUID, revision int64) (int, error) {
	if !s.testSales {
		return 0, ErrSalesDisabled
	}
	var status int
	err := s.db.QueryRowContext(ctx, `SELECT public.content_test_purchase($1,$2,$3,$4)`, id, buyer, request, revision).Scan(&status)
	return status, err
}

func (s *Store) RevokeTestOrder(ctx context.Context, buyer, request uuid.UUID) error {
	if !s.testSales {
		return ErrSalesDisabled
	}
	var found bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_test_revoke($1,$2)`, buyer, request).Scan(&found)
	if err == nil && !found {
		return ErrPostNotFound
	}
	return err
}

type TestReceipt struct {
	Request     uuid.UUID  `json:"request_id"`
	Post        uuid.UUID  `json:"post_id"`
	Revision    int64      `json:"revision"`
	Amount      int64      `json:"amount_minor"`
	Currency    string     `json:"currency"`
	ConfirmedAt time.Time  `json:"confirmed_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) TestReceipt(ctx context.Context, buyer, request uuid.UUID) (TestReceipt, error) {
	receipt := TestReceipt{Request: request}
	if !s.testSales {
		return receipt, ErrSalesDisabled
	}
	err := s.db.QueryRowContext(ctx, `SELECT post_id,revision,amount_minor,currency,confirmed_at,revoked_at FROM public.content_test_receipt($1,$2)`, buyer, request).Scan(&receipt.Post, &receipt.Revision, &receipt.Amount, &receipt.Currency, &receipt.ConfirmedAt, &receipt.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, ErrPostNotFound
	}
	return receipt, err
}

type TestReceiptCursor struct {
	Request     uuid.UUID
	ConfirmedAt time.Time
}

func (s *Store) TestReceipts(ctx context.Context, buyer uuid.UUID, limit int, before *TestReceiptCursor) ([]TestReceipt, error) {
	if !s.testSales {
		return nil, ErrSalesDisabled
	}
	if buyer == uuid.Nil || limit < 1 || limit > 41 {
		return nil, ErrInvalidFilter
	}

	var beforeTime *time.Time
	var beforeRequest *uuid.UUID
	if before != nil {
		beforeTime = &before.ConfirmedAt
		beforeRequest = &before.Request
	}

	const query = `SELECT request_id,post_id,revision,amount_minor,currency,confirmed_at,revoked_at
		FROM public.content_test_receipts($1,$2,$3,$4) ORDER BY confirmed_at DESC,request_id DESC`
	rows, err := s.db.QueryContext(ctx, query, buyer, beforeTime, beforeRequest, limit)
	if err != nil {
		return nil, fmt.Errorf("list test receipts: %w", err)
	}
	defer rows.Close()

	receipts := make([]TestReceipt, 0, limit)
	for rows.Next() {
		var receipt TestReceipt
		if err := rows.Scan(&receipt.Request, &receipt.Post, &receipt.Revision, &receipt.Amount,
			&receipt.Currency, &receipt.ConfirmedAt, &receipt.RevokedAt); err != nil {
			return nil, fmt.Errorf("read test receipt: %w", err)
		}
		receipts = append(receipts, receipt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read test receipts: %w", err)
	}
	return receipts, nil
}
