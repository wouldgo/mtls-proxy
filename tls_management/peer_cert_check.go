package tls_management

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

const (
	peerValidationErr = "peer certificate validation error: %w"
)

var (
	errNoCertsFound           = errors.New("no certificates found")
	errNoClientCertAndCAFound = errors.New("not enough certificates")
	errNoOCSPServerFound      = errors.New("no ocsp server found")
)

type TLSChecker func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
type CheckerOpts struct {
	Logger         *log.Log
	IgnoreTLSCheck bool
}

func NewChecker(checkerOpts *CheckerOpts) (TLSChecker, error) {
	if checkerOpts.IgnoreTLSCheck {
		checker := &noopChecker{
			logger: checkerOpts.Logger,
		}
		return checker.Check, nil
	}

	httpClient := &http.Client{}
	ocspRequestOptions := &ocsp.RequestOptions{Hash: crypto.SHA256}
	checker := &checker{
		logger:             checkerOpts.Logger,
		httpClient:         httpClient,
		ocspRequestOptions: ocspRequestOptions,
	}

	return checker.Check, nil
}

type checker struct {
	logger             *log.Log
	httpClient         *http.Client
	ocspRequestOptions *ocsp.RequestOptions
}

func (c *checker) doOCSPRequest(
	ocspURL string,
	peerCertificate *x509.Certificate,
	issuerCertificate *x509.Certificate,
) (*ocsp.Response, error) {
	buffer, err := ocsp.CreateRequest(
		peerCertificate,
		issuerCertificate,
		c.ocspRequestOptions,
	)
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	remoteURL, err := url.Parse(ocspURL)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", remoteURL.Host)

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	ocspResponse, err := ocsp.ParseResponse(output, nil) //XXX if I put issuerCert explodes
	if err != nil {
		return nil, err
	}

	return ocspResponse, nil
}

func (c *checker) validateOCSP(peerCertificate *x509.Certificate, issuerCertificate *x509.Certificate) error {
	if len(peerCertificate.OCSPServer) == 0 {
		return errNoOCSPServerFound
	}
	ocspURL := peerCertificate.OCSPServer[0]

	response, err := c.doOCSPRequest(ocspURL, peerCertificate, issuerCertificate)
	if err != nil {
		return err
	}

	if response.Status != 0 {
		return fmt.Errorf("ocsp status %d", response.Status)
	}
	err = response.CheckSignatureFrom(issuerCertificate)
	if err != nil {
		return err
	}
	return nil
}

func (c *checker) Check(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	c.logger.Debug("checker called")
	if len(verifiedChains) == 0 {
		return errNoCertsFound
	}
	firstChain := verifiedChains[0]

	if len(firstChain) < 1 {
		return fmt.Errorf(peerValidationErr, errNoClientCertAndCAFound)
	}

	peerCertificate := firstChain[0]
	issuerCert := firstChain[1]

	c.logger.Info("checking certificate", zap.Any("peerCertificate", peerCertificate), zap.Any("issuerCertificate", issuerCert))
	//TODO logging...
	err := c.validateOCSP(peerCertificate, issuerCert)
	if err != nil {
		return fmt.Errorf(peerValidationErr, err)
	}
	return nil
}

type noopChecker struct {
	logger *log.Log
}

func (n *noopChecker) Check(_ [][]byte, _ [][]*x509.Certificate) error {
	n.logger.Debug("noop checker called")
	return nil
}
