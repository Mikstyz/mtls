// Command upload-server receives files in private quarantine.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mtls/media-processing/internal/authupload"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/runconfig"
	"mtls/media-processing/internal/uploadhttp"
	"mtls/media-processing/internal/userclient"
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
	settings := service.Upload
	host, _, err := net.SplitHostPort(settings.Address)
	if err != nil || (settings.CertFile == "") != (settings.KeyFile == "") {
		return errors.New("invalid upload listener settings")
	}

	ip := net.ParseIP(host)
	if settings.CertFile == "" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("remote upload requires HTTPS")
	}

	private, _, err := runconfig.StoragePaths(service.PhotoQueue.Quarantine, service.PhotoQueue.Prepared)
	if err != nil {
		return err
	}

	files, err := quarantine.Open(private)
	if err != nil {
		return err
	}
	defer files.Close()

	users, err := userclient.New(settings.UserURL, settings.UserSecret, settings.CookieName, settings.UserTLS)
	if err != nil {
		return errors.New("invalid upload user connection settings")
	}

	db, err := cfg.OpenDatabase(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	uploads, err := authupload.New(startup, lifecycle.New(db), files, users, lifecycle.Quota{
		MaxAssets: settings.OwnerMaxAssets, MaxBytes: settings.OwnerMaxBytes,
		GlobalMaxAssets: settings.GlobalMaxAssets, GlobalMaxBytes: settings.GlobalMaxBytes,
	})
	cancel()
	if err != nil {
		return err
	}

	handler, err := uploadhttp.New(uploads, settings.Origin, settings.CookieName, settings.MaxFileBytes, settings.MaxConcurrent)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: settings.Address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Minute,
		WriteTimeout: 16 * time.Minute, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	done := make(chan error, 1)
	go func() {
		if settings.CertFile != "" {
			done <- server.ListenAndServeTLS(settings.CertFile, settings.KeyFile)
		} else {
			done <- server.ListenAndServe()
		}
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
		return nil
	}
}
