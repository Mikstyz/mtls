package lifecycle

import (
	"context"
	"database/sql"
	"fmt"
)

type globalUsage struct {
	assets  int64
	bytes   int64
	unknown int64
}

func (q Quota) valid() bool {
	return q.MaxAssets >= 1 && q.MaxAssets <= 1_000_000 &&
		q.MaxBytes >= 1 && q.MaxBytes <= 1<<50 &&
		q.GlobalMaxAssets >= 1 && q.GlobalMaxAssets <= 10_000_000 &&
		q.GlobalMaxBytes >= 1 && q.GlobalMaxBytes <= 1<<60
}

// ConfigureQuota checks that the separately configured shared limits match this instance.
func (s *Store) ConfigureQuota(ctx context.Context, quota Quota) error {
	if ctx == nil || s == nil || s.db == nil || !quota.valid() {
		return ErrInvalid
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin media quota configuration: %w", err)
	}

	defer tx.Rollback()

	if _, err := lockGlobalQuota(ctx, tx, quota); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit media quota configuration: %w", err)
	}

	return nil
}

func lockGlobalQuota(ctx context.Context, tx *sql.Tx, quota Quota) (globalUsage, error) {
	const query = `SELECT assets, original_bytes, unknown_assets, owner_max_assets, owner_max_bytes,
		global_max_assets, global_max_bytes FROM public.media_lock_usage()`

	var usage globalUsage
	var ownerAssets, ownerBytes, maxAssets, maxBytes sql.NullInt64

	if err := tx.QueryRowContext(ctx, query).Scan(&usage.assets, &usage.bytes, &usage.unknown, &ownerAssets, &ownerBytes, &maxAssets, &maxBytes); err != nil {
		return globalUsage{}, fmt.Errorf("lock global media quota: %w", err)
	}

	if !ownerAssets.Valid || !ownerBytes.Valid || !maxAssets.Valid || !maxBytes.Valid || ownerAssets.Int64 != quota.MaxAssets || ownerBytes.Int64 != quota.MaxBytes || maxAssets.Int64 != quota.GlobalMaxAssets || maxBytes.Int64 != quota.GlobalMaxBytes {
		return globalUsage{}, ErrQuotaConfiguration
	}

	return usage, nil
}
