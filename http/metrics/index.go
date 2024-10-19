package http_metrics

import (
	"context"
	"net/http"

	"golang.org/x/sync/errgroup"

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

func (c *MetricsServer) Listen(ctx context.Context, addr string) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {

		return http.ListenAndServe(addr, c.router)
	})

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (c *MetricsServer) Close(ctx context.Context) error {
	return nil
}
