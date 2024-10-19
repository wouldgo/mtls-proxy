package proxy

import (
	"crypto/tls"
	"io"
	"net/http"

	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
	"gopkg.in/elazarl/goproxy.v1"
)

var (
	_ Performer = (*mtlsPerformer)(nil)
)

type Performer interface {
	Perform(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)
}

type mtlsPerformer struct {
	log    *zap.Logger
	client *http.Client
}

type MTLSPerformerOpts struct {
	Log       *log.Log
	TlsConfig *tls.Config
}

func NewMtlsPerformer(mtlsPerformerOpts *MTLSPerformerOpts) (Performer, error) {
	client := &http.Client{
		// Transport: &http.Transport{
		// 	TLSClientConfig: mtlsPerformerOpts.TlsConfig,
		// },
	}

	return &mtlsPerformer{
		log:    mtlsPerformerOpts.Log.Logger,
		client: client,
	}, nil
}

func (m mtlsPerformer) Perform(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	m.log.Info("http connection", zap.String("host", req.URL.Host))

	oldReqURI := req.RequestURI
	req.RequestURI = ""
	resp, err := m.client.Do(req)
	if err != nil {
		m.log.Sugar().Errorf("Error calling %+v: %w", req, err)
		return req, &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     http.StatusText(http.StatusUnauthorized),
			Body:       io.NopCloser(unathorizedReader),
			Header:     make(http.Header),
		}
	}
	req.RequestURI = oldReqURI
	return req, resp
}
