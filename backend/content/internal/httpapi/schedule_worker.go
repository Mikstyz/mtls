package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mtls/content/internal/catalog"
	sharedconfig "mtls/shared/config"
)

func StartScheduledPosts(ctx context.Context, store *catalog.Store, address, cookieName, secret string, userTLS sharedconfig.ServiceTLS) (func(), error) {
	if len(secret) < 32 || len(secret) > 128 || strings.ContainsFunc(secret, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return nil, errors.New("invalid scheduled publication credential")
	}

	users, err := newUserClient(address, cookieName, userTLS)
	if err != nil {
		return nil, err
	}

	worker, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer users.client.CloseIdleConnections()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-worker.Done():
				return
			case <-ticker.C:
				if err := publishOneScheduled(worker, store, users, secret); err != nil && worker.Err() == nil {
					log.Print("scheduled publication unavailable")
				}
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}

func publishOneScheduled(ctx context.Context, store *catalog.Store, users *userClient, secret string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	job, err := store.ClaimScheduledPost(ctx)
	if err != nil || job == nil {
		return err
	}
	if len(job.MediaIDs) == 0 || len(job.MediaIDs) > 16 {
		return nil
	}

	params := url.Values{"owner": {job.AuthorID.String()}, "kind": {job.Kind}, "media": job.MediaIDs}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, users.url+"/internal/content/publication-check?"+params.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Internal-Secret", secret)

	resp, err := users.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil
	case http.StatusNoContent:
		duration, err := readMediaDuration(resp.Header, job.Kind)
		if err != nil {
			return err
		}
		return store.PublishScheduledPost(ctx, *job, duration)
	default:
		return errors.New("publication check unavailable")
	}
}
