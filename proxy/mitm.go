package proxy

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/elazarl/goproxy"
	"github.com/wouldgo/mtls-proxy/tls_management"
)

var (
	_ goproxy.HttpsHandler = (*mitmHandler)(nil)
)

type mitmHandler struct {
	certificateAuthorityForge tls_management.CertificateAuthorityForge
}

type MitmHandlerOpts struct {
	CertificateAuthorityForge tls_management.CertificateAuthorityForge
}

func NewMitmHandler(mitmHandlerOpts *MitmHandlerOpts) (goproxy.HttpsHandler, error) {
	return &mitmHandler{
		certificateAuthorityForge: mitmHandlerOpts.CertificateAuthorityForge,
	}, nil
}

func (c *mitmHandler) HandleConnect(req string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			config := tls.Config{}

			onlyHost, _, err := net.SplitHostPort(host)
			if err != nil {
				return nil, fmt.Errorf("%s cannot be splitted in host:port: %w", host, err)
			}

			cert, err := c.certificateAuthorityForge.GenerateKey(onlyHost)
			if err != nil {
				ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
				return nil, err
			}
			config.Certificates = append(config.Certificates, cert)
			return &config, nil
		},
	}, req
}
