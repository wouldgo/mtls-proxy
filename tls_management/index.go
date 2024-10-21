package tls_management

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	log "github.com/wouldgo/mtls-proxy/logging"
	"golang.org/x/sync/errgroup"
)

const (
	emptyStr         = "-"
	tlsOptionsErrStr = "tls options error: %w"
	tlsConfigErrStr  = "tls config error (%s): %w"
)

type CredentialRetriver interface {
	Get(ctx context.Context) (*tls.Certificate, *x509.CertPool, error)
	Close(ctx context.Context) error
}

type TLSCheckerOpts struct {
	Logger             *log.Log
	TLSChecker         TLSChecker
	CredentialRetriver CredentialRetriver
}

func (o *Opts) TlsConfig(
	ctx context.Context,
	tlsCheckerOpts *TLSCheckerOpts,
) (*tls.Config, error) {
	ctx, stop := context.WithTimeout(ctx, 20*time.Second)
	g, ctx := errgroup.WithContext(ctx)
	defer stop()
	var (
		cert       *tls.Certificate
		caCertPool *x509.CertPool
		err        error
	)
	g.Go(func() error {
		cert, caCertPool, err = tlsCheckerOpts.CredentialRetriver.Get(ctx)
		defer tlsCheckerOpts.CredentialRetriver.Close(ctx)
		return err
	})

	err = g.Wait()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			tlsCheckerOpts.Logger.Debug("Checking TLS certificates:")
			for i, cert := range cs.PeerCertificates {
				tlsCheckerOpts.Logger.Sugar().Debugf("Server certificate %d: Issuer: %s, Subject: %s", i, cert.Issuer, cert.Subject)
			}

			if cs.VerifiedChains != nil && cs.VerifiedChains[0] != nil {

				for i, cert := range cs.VerifiedChains[0] {
					tlsCheckerOpts.Logger.Sugar().Debugf("Client certificate %d: Issuer: %s, Subject: %s", i, cert.Issuer, cert.Subject)
				}
			}

			return nil
		},
		VerifyPeerCertificate: tlsCheckerOpts.TLSChecker,
	}, nil
}
