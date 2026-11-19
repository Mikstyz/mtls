package health

import (
	"context"
	"database/sql"
	"net/http"
	"time"
)

func Database(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Ready checks the local database and the peer's authenticated local health.
func Ready(w http.ResponseWriter, r *http.Request, db *sql.DB, client *http.Client, peerURL, secret string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL+"/internal/health", nil)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	req.Header.Set("X-Internal-Secret", secret)
	resp, err := client.Do(req)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
