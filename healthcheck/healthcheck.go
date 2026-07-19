package healthcheck

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func NewServer(port int) (*http.Server, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid health check port number: %v", port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "ok")
	})

	p := ":" + strconv.Itoa(port)
	return &http.Server{
		Addr:              p,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}
