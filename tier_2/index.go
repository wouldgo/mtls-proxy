package tier_2

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/proxy"
	"go.uber.org/zap"
)

var (
	unathorizedReader                 = strings.NewReader("Not Authorized")
	_                 proxy.Performer = (*mtlsPerformer)(nil)
)

type mtlsPerformer struct {
	log                      *zap.Logger
	mtlsClient, client       *http.Client
	mtlsTlsConfig, tlsConfig *tls.Config
	unauthErr                http.Response
}

type MTLSPerformerOpts struct {
	Log       *log.Log
	TlsConfig *tls.Config
}

func NewMtlsPerformer(mtlsPerformerOpts *MTLSPerformerOpts) (proxy.Performer, error) {
	mtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtlsPerformerOpts.TlsConfig,
		},
	}
	tlsConfig := &tls.Config{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &mtlsPerformer{
		log:           mtlsPerformerOpts.Log.Logger,
		mtlsClient:    mtlsClient,
		client:        client,
		mtlsTlsConfig: mtlsPerformerOpts.TlsConfig,
		tlsConfig:     tlsConfig,
		unauthErr: http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     http.StatusText(http.StatusUnauthorized),
			Body:       io.NopCloser(unathorizedReader),
			Header:     make(http.Header),
		},
	}, nil
}

func (m *mtlsPerformer) PerformHTTP(req *http.Request) *http.Response {
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
			m.log.Warn("mtls call in error trying tls", zap.Error(targetErr))
			resp, err = m.client.Do(req)
			if err != nil {
				m.log.Error("error calling in tls", zap.Any("request", req), zap.Error(err))
				return &m.unauthErr
			}
			return resp
		}
		m.log.Error("error calling in mtls", zap.Any("request", req), zap.Error(err))
		return &m.unauthErr
	}
	return resp
}

func (m *mtlsPerformer) PerformWS(req *http.Request) (net.Conn, error) {
	m.log.Info("mtls websocket connection", zap.String("host", req.URL.Host))

	targetConn, err := tls.Dial("tcp", req.URL.Host, m.mtlsTlsConfig)
	if err != nil {
		var targetErr x509.UnknownAuthorityError
		if errors.As(err, &targetErr) {
			m.log.Error("mtls websocket dial in error trying tls", zap.Error(err))
			targetConn, err = tls.Dial("tcp", req.URL.Host, m.tlsConfig)
			if err != nil {
				m.log.Error("error dial websocket in tls", zap.Any("request", req), zap.Error(err))
				return nil, fmt.Errorf("tls websocket dial in error: %w", err)
			}
			return targetConn, nil
		}
		m.log.Error("tls websocket dial in error", zap.Any("request", req), zap.Error(err))
		return nil, fmt.Errorf("websocket dialing in error: %w", err)
	}

	//TODO recurrent ephmeralproof renewal

	return targetConn, nil
}
