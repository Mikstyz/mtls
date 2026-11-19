package main

import (
	"context"
	"database/sql"
	"log"
	"time"
)

func startViewReceiptPruning(db *sql.DB) func() {
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			pruneViewReceipts(ctx, db)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return func() {
		stop()
		<-done
	}
}

func pruneViewReceipts(ctx context.Context, db *sql.DB) {
	for range 16 {
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		var removed int
		err := db.QueryRowContext(queryCtx, `SELECT public.content_prune_view_receipts()`).Scan(&removed)
		cancel()

		if err != nil {
			if ctx.Err() == nil {
				log.Printf("prune post view receipts: %v", err)
			}
			return
		}

		if removed < 1000 {
			return
		}
	}
}
