// Package health provides /livez and /readyz HTTP handlers.
package health

import (
	"net/http"

	"gorm.io/gorm"
)

// LivezHandler returns 200 as long as the process is alive.
func LivezHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// ReadyzHandler returns 200 when the state database is reachable.
func ReadyzHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sqlDB, err := db.DB()
		if err != nil {
			http.Error(w, "db error: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if err := sqlDB.PingContext(r.Context()); err != nil {
			http.Error(w, "db not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
