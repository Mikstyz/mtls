// Command photo-queue prepares quarantined photos for later publication.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"mtls/media-processing/internal/deletion"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/photo"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/runconfig"
	"mtls/media-processing/internal/storage"
	"mtls/media-processing/internal/userclient"
	sharedconfig "mtls/shared/config"
)

const (
	jobTimeout = 6 * time.Minute
	jobLease   = 7 * time.Minute
)

func main() {
	path := flag.String("config", "config.toml", "path to TOML configuration")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *path); err != nil && !errors.Is(err, context.Canceled) {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path string) error {
	var cfg runconfig.Config

	if err := sharedconfig.Load(path, &cfg); err != nil {
		return err
	}

	settings := cfg.Services.MediaProcessing.PhotoQueue
	ttl := settings.ReservationTTLSeconds
	if ttl == 0 {
		ttl = 24 * 60 * 60
	}
	if ttl < 3600 || ttl > 30*24*60*60 {
		return errors.New("reservation_ttl_seconds must be between one hour and 30 days")
	}

	quarantinePath, preparedPath, err := runconfig.StoragePaths(settings.Quarantine, settings.Prepared)
	if err != nil {
		return err
	}

	processor, err := photo.NewProcessor(settings.Systemd, settings.Supervisor, settings.Bubblewrap, settings.Worker, 1, 5*time.Minute)
	if err != nil {
		return err
	}

	private, err := quarantine.Open(quarantinePath)
	if err != nil {
		return err
	}
	defer private.Close()

	prepared, err := storage.Open(preparedPath)
	if err != nil {
		return err
	}
	defer prepared.Close()

	db, err := cfg.OpenDatabase(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	peer := cfg.Services.MediaProcessing.Upload
	users, err := userclient.New(peer.UserURL, peer.UserSecret, peer.CookieName, peer.UserTLS)

	if err != nil {
		return err
	}

	ledger := lifecycle.New(db)
	cleaner := deletion.New(ledger, private, prepared, users)
	nextOwnerPurge := time.Now()
	nextSweep := time.Now()
	for ctx.Err() == nil {
		if !time.Now().Before(nextOwnerPurge) {
			poll, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := purgeOwner(poll, ledger, users)
			cancel()
			nextOwnerPurge = time.Now().Add(2 * time.Second)
			if err != nil && ctx.Err() == nil {
				log.Print("media owner cleanup unavailable")
				nextOwnerPurge = time.Now().Add(15 * time.Second)
			}
		}
		if !time.Now().Before(nextSweep) {
			sweep, cancel := context.WithTimeout(ctx, 15*time.Second)
			expired, expiryErr := ledger.ExpireReservations(sweep, ttl)
			_, privateErr := private.CleanPartials(sweep, 100)
			_, preparedErr := prepared.CleanStages(sweep, 100)
			cancel()
			nextSweep = time.Now().Add(5 * time.Minute)
			if expired == 100 {
				nextSweep = time.Now().Add(time.Second)
			}
			if expiryErr != nil || privateErr != nil || preparedErr != nil {
				nextSweep = time.Now().Add(30 * time.Second)
				if ctx.Err() == nil {
					log.Print("media queue could not finish temporary file cleanup")
				}
			}
		}

		cleanup, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := cleanNext(cleanup, ledger, cleaner); err != nil && ctx.Err() == nil {
			log.Print("photo queue could not clean media deletion")
		}
		cancel()

		delivery, cancel := context.WithTimeout(ctx, 7*time.Second)
		if err := deliverReady(delivery, ledger, users); err != nil && ctx.Err() == nil {
			log.Print("photo queue could not deliver ready event")
		}
		cancel()

		claim, cancel := context.WithTimeout(ctx, 5*time.Second)
		id, lease, err := ledger.ClaimNextPhoto(claim, jobLease)
		cancel()

		if err != nil {
			delay := time.Second
			if !errors.Is(err, lifecycle.ErrNotFound) && ctx.Err() == nil {
				log.Print("photo queue could not claim a job")
				delay = 5 * time.Second
			}

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			continue
		}

		job, cancel := context.WithTimeout(ctx, jobTimeout)
		err = photo.StoreQuarantinedPhoto(job, prepared, private, processor, ledger, id, lease, 1600)
		cancel()

		if err != nil && ctx.Err() == nil {
			log.Printf("photo job %s failed", id)

			retry, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := ledger.FailPhoto(retry, id, lease, 30*time.Second)
			cancel()
			if err != nil && !errors.Is(err, lifecycle.ErrConflict) && ctx.Err() == nil {
				log.Printf("photo job %s could not schedule retry", id)
			}
		}
	}

	return ctx.Err()
}

func deliverReady(ctx context.Context, ledger *lifecycle.Store, users *userclient.Client) error {
	event, err := ledger.NextReadyEvent(ctx)

	if errors.Is(err, lifecycle.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	if err := users.MarkReady(ctx, event.OwnerID, event.AssetID, event.Kind, event.DurationMillis); err != nil {
		return errors.Join(err, ledger.DeferReady(ctx, event.AssetID))
	}

	return ledger.AcknowledgeReady(ctx, event.AssetID)
}

func cleanNext(ctx context.Context, ledger *lifecycle.Store, cleaner *deletion.Service) error {
	owner, id, err := ledger.NextDeletion(ctx)

	if errors.Is(err, lifecycle.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	if err := cleaner.Clean(ctx, owner, id); err != nil {
		return errors.Join(err, ledger.DeferDeletion(ctx, id))
	}

	return nil
}

func purgeOwner(ctx context.Context, ledger *lifecycle.Store, users *userclient.Client) error {
	owner, err := users.NextPurge(ctx)
	if err != nil || owner == uuid.Nil {
		return err
	}
	done, err := ledger.PurgeOwnerBatch(ctx, owner)
	if err != nil || !done {
		return err
	}
	return users.FinishPurge(ctx, owner)
}
