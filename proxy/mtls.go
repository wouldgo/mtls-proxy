package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"

	"github.com/elazarl/goproxy"
	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
)

var (
	_ Performer = (*mtlsPerformer)(nil)
)

type Performer interface {
	Perform(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)
}

type mtlsPerformer struct {
	log                *zap.Logger
	mtlsClient, client *http.Client
	unauthErr          http.Response
}

type MTLSPerformerOpts struct {
	Log       *log.Log
	TlsConfig *tls.Config
}

func NewMtlsPerformer(mtlsPerformerOpts *MTLSPerformerOpts) (Performer, error) {
	mtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtlsPerformerOpts.TlsConfig,
		},
	}
	client := &http.Client{}

	return &mtlsPerformer{
		log:        mtlsPerformerOpts.Log.Logger,
		mtlsClient: mtlsClient,
		client:     client,
		unauthErr: http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     http.StatusText(http.StatusUnauthorized),
			Body:       io.NopCloser(unathorizedReader),
			Header:     make(http.Header),
		},
	}, nil
}

func (m mtlsPerformer) Perform(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	m.log.Info("mtls performer is performing")
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			m.log.Info("request is a websocket passing it")
			return req, nil
		}
	}

	m.log.Info("http connection", zap.String("host", req.URL.Host))
	oldReqURI := req.RequestURI
	defer func() {
		req.RequestURI = oldReqURI
	}()
	req.RequestURI = ""
	resp, err := m.mtlsClient.Do(req)
	if err != nil {
		var targetErr x509.UnknownAuthorityError
		if errors.As(err, &targetErr) {
			m.log.Warn("mtls call in error trying tls...", zap.Error(targetErr))
			resp, err = m.client.Do(req)
			if err != nil {
				m.log.Error("error calling in tls", zap.Any("request", req), zap.Error(err))
				return req, &m.unauthErr
			}
			return req, resp
		}
		m.log.Error("error calling in mtls", zap.Any("request", req), zap.Error(err))
		return req, &m.unauthErr
	}
	return req, resp
}
