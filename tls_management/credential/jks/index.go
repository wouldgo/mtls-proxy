package jks_credential

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/wouldgo/mtls-proxy/tls_management"
	"go.uber.org/zap"
)

var (
	_ tls_management.CredentialRetriver = (*jksCredentialRetriever)(nil)
)

type jksCredentialRetriever struct {
	log      *zap.Logger
	ks       keystore.KeyStore
	password []byte
	entry    string
}

type JKSCredentialRetriverOpts struct {
	Log  *zap.Logger
	Opts *Opts
}

func NewJksCredentialRetriver(
	jksCredentialRetriverOpts *JKSCredentialRetriverOpts,
) (tls_management.CredentialRetriver, error) {
	jksBytes, err := os.ReadFile(jksCredentialRetriverOpts.Opts.jksPath)
	if err != nil {
		return nil, fmt.Errorf("jks credential retriver error: %w", err)
	}

	password := []byte(jksCredentialRetriverOpts.Opts.jksPassword)

	ks := keystore.New()
	err = ks.Load(bytes.NewReader(jksBytes), password)
	if err != nil {
		return nil, fmt.Errorf("jks credential retriver error: %w", err)
	}

	return &jksCredentialRetriever{
		log:      jksCredentialRetriverOpts.Log,
		ks:       ks,
		password: password,
		entry:    jksCredentialRetriverOpts.Opts.jksEntry,
	}, nil
}

func (j *jksCredentialRetriever) Get(ctx context.Context) (*tls.Certificate, *x509.CertPool, error) {
	var (
		intermediateCerts [][]byte
		privateKey        crypto.PrivateKey
		x509Cert          *x509.Certificate
		err               error
	)
	caCertPool := x509.NewCertPool()

	privateKeyEntry, err := j.ks.GetPrivateKeyEntry(j.entry, j.password)
	if err != nil {
		return nil, nil, fmt.Errorf("jks credential retriever error: %w", err)
	}
	for _, val := range privateKeyEntry.CertificateChain {

		aCert, err := x509.ParseCertificate(val.Content)
		if err != nil {
			return nil, nil, fmt.Errorf("jks credential retriver error: %w", err)
		}
		if !aCert.IsCA {
			x509Cert = aCert
		} else {
			intermediateCerts = append(intermediateCerts, aCert.Raw)
			caCertPool.AddCert(aCert)
		}
	}

	if x509Cert == nil {
		return nil, nil, fmt.Errorf("jks credential retriver error: %w", errors.New("none of the certificates are client?"))
	}

	privateKey, err = x509.ParsePKCS8PrivateKey(privateKeyEntry.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("jks credential retriver error: %w", err)
	}

	return &tls.Certificate{
		Certificate: append([][]byte{x509Cert.Raw}, intermediateCerts...),
		PrivateKey:  privateKey,
		Leaf:        x509Cert,
	}, caCertPool, nil
}

func (*jksCredentialRetriever) Close(ctx context.Context) error {
	return nil
}
