package httpapi

import (
	"fmt"
	"net/http"
)

func (h *Handler) doPeerRequest(request *http.Request) (*http.Response, error) {
	h.peerRequests.Add(1)

	response, err := h.client.Do(request)

	if err != nil || response.StatusCode >= http.StatusInternalServerError {
		h.peerFailures.Add(1)
	}

	return response, err
}

// internalMetrics exposes aggregate peer counters only to an authenticated peer.
func (h *Handler) internalMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# TYPE mtls_user_peer_requests_total counter\nmtls_user_peer_requests_total %d\n"+
		"# TYPE mtls_user_peer_failures_total counter\nmtls_user_peer_failures_total %d\n",
		h.peerRequests.Load(), h.peerFailures.Load())
}
