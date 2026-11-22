//go:build linux

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

	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/runconfig"
	"mtls/media-processing/internal/storage"
	"mtls/media-processing/internal/video"
	sharedconfig "mtls/shared/config"
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
	service := cfg.Services.MediaProcessing
	settings := service.VideoQueue
	common := service.PhotoQueue
	if settings.MaxOutputBytes < 1 || settings.MaxOutputBytes > 1<<40 || settings.JobTimeoutSeconds < 1 || settings.JobTimeoutSeconds > 21600 ||
		settings.MaxDurationSeconds < 1 || settings.MaxDurationSeconds > 86400 || service.Upload.MaxFileBytes < 1 || service.Upload.MaxFileBytes > 1<<40 {
		return errors.New("invalid video worker limits")
	}
	timeout := time.Duration(settings.JobTimeoutSeconds) * time.Second
	processor, err := video.NewProcessor(common.Systemd, settings.Supervisor, common.Bubblewrap, settings.Runtime, 1, timeout)
	if err != nil {
		return err
	}
	privatePath, preparedPath, err := runconfig.StoragePaths(common.Quarantine, common.Prepared)
	if err != nil {
		return err
	}
	for _, path := range []string{privatePath, preparedPath} {
		if _, _, err := runconfig.StoragePaths(path, settings.Runtime); err != nil {
			return err
		}
	}
	private, err := quarantine.Open(privatePath)
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

	ledger := lifecycle.New(db)
	job := video.Job{Processor: processor, Ledger: ledger, Quarantine: private, Prepared: prepared,
		Limits:   video.ProbeLimits{Duration: time.Duration(settings.MaxDurationSeconds) * time.Second, Pixels: 64_000_000, FPS: 240},
		MaxInput: service.Upload.MaxFileBytes, MaxOutput: settings.MaxOutputBytes}

	for ctx.Err() == nil {
		claim, cancel := context.WithTimeout(ctx, 5*time.Second)
		id, lease, err := ledger.ClaimNextVideo(claim, timeout+time.Minute)
		cancel()
		if err != nil {
			if !errors.Is(err, lifecycle.ErrNotFound) && ctx.Err() == nil {
				log.Print("video queue could not claim a job")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}

		work, cancel := context.WithTimeout(ctx, timeout)
		err = job.Process(work, id, lease)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("video job %s failed: %v", id, err)
			retry, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = ledger.FailVideo(retry, id, lease, 30*time.Second)
			cancel()
			if err != nil && !errors.Is(err, lifecycle.ErrConflict) {
				log.Printf("video job %s could not schedule retry", id)
			}
		}
	}
	return ctx.Err()
}
