package pem_credential

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"

	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/tls_management"
)

var (
	_ tls_management.CredentialRetriver = (*pemCredentialRetriever)(nil)
)

type pemCredentialRetriever struct {
	log                   *log.Log
	fullChain, privateKey []byte
}

type PemCredentialRetriverOpts struct {
	Log  *log.Log
	Opts *Opts
}

func NewPemCredentialRetriver(
	pemCredentialRetriverOpts *PemCredentialRetriverOpts,
) (tls_management.CredentialRetriver, error) {
	fullChain, err := os.ReadFile(path.Join(pemCredentialRetriverOpts.Opts.pemCredFolder, pemCredentialRetriverOpts.Opts.pemFullChain))
	if err != nil {
		return nil, fmt.Errorf("pem credential retriver error: %w", err)
	}

	privateKey, err := os.ReadFile(path.Join(pemCredentialRetriverOpts.Opts.pemCredFolder, pemCredentialRetriverOpts.Opts.pemPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("pem credential retriver error: %w", err)
	}

	return &pemCredentialRetriever{
		log:        pemCredentialRetriverOpts.Log,
		fullChain:  fullChain,
		privateKey: privateKey,
	}, nil
}

func (f *pemCredentialRetriever) Get(ctx context.Context) (*tls.Certificate, *x509.CertPool, error) {
	var (
		intermediateCerts [][]byte
		privateKey        crypto.PrivateKey
		x509Cert          *x509.Certificate
		err               error
	)

	caCertPool := x509.NewCertPool()
	for {
		block, rest := pem.Decode(f.privateKey)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" {
			f.privateKey = rest
			continue
		}

		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("pem credential retriever error: %w", err)
		}
		f.privateKey = rest
	}

	for {
		block, rest := pem.Decode(f.fullChain)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			f.fullChain = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}

		if !cert.IsCA && x509Cert == nil {
			x509Cert = cert
		} else {
			intermediateCerts = append(intermediateCerts, cert.Raw)
			caCertPool.AddCert(cert)
		}
		f.fullChain = rest
	}

	if x509Cert == nil {
		return nil, nil, fmt.Errorf("pem credential retriever error: %w", errors.New("none of the certificates are client?"))
	}

	return &tls.Certificate{
		Certificate: append([][]byte{x509Cert.Raw}, intermediateCerts...),
		PrivateKey:  privateKey,
		Leaf:        x509Cert,
	}, caCertPool, nil
}
