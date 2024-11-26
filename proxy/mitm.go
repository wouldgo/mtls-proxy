package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/wouldgo/mtls-proxy/tls_management"
)

var (
	_ HttpsHandler = (*mitmHandler)(nil)
)

type TLSHandle func(host string) (*tls.Config, error)

type HttpsHandler interface {
	HandleConnect() TLSHandle
}

type mitmHandler struct {
	certificateAuthorityForge tls_management.CertificateAuthorityForge
}

type MitmHandlerOpts struct {
	CertificateAuthorityForge tls_management.CertificateAuthorityForge
}

func NewMitmHandler(mitmHandlerOpts *MitmHandlerOpts) (HttpsHandler, error) {
	return &mitmHandler{
		certificateAuthorityForge: mitmHandlerOpts.CertificateAuthorityForge,
	}, nil
}

func (c *mitmHandler) HandleConnect() TLSHandle {
	return func(host string) (*tls.Config, error) {
		config := tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		onlyHost, _, err := net.SplitHostPort(host)
		if err != nil {
			oldErr := fmt.Errorf("%s cannot be splitted in host:port: %w", host, err)
			cert, err := c.certificateAuthorityForge.GenerateKey(host)
			if err != nil {
				return nil, errors.Join(oldErr, err)
			}

			config.Certificates = append(config.Certificates, cert)
			return &config, nil
		}

		cert, err := c.certificateAuthorityForge.GenerateKey(onlyHost)
		if err != nil {
			err := fmt.Errorf("cannot sign host certificate with provided CA: %w", err)
			return nil, err
		}
		config.Certificates = append(config.Certificates, cert)
		return &config, nil
	}
}
