package http_metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/wouldgo/mtls-proxy/logging"
)

type MetricsServer struct {
	router *http.ServeMux
}

type MetricsServerOpts struct {
	Log *log.Log
}

func NewMetricsServer(certificateAuthorityServerOpts *MetricsServerOpts) (*MetricsServer, error) {
	toReturn := &MetricsServer{
		router: http.NewServeMux(),
	}

	toReturn.router.Handle("GET /metrics", promhttp.Handler())
	toReturn.router.HandleFunc("GET /up", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	return toReturn, nil
}

func (m *MetricsServer) Handler() http.Handler {
	return m.router
}
