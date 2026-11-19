package httpapi

import "net/http"

// RecoveryMode prevents access to restored content until reconciliation.
func RecoveryMode(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health" && r.URL.RawQuery == "" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
}
