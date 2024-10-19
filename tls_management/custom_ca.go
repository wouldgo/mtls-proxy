package tls_management

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"sort"
	"time"

	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
)

const (
	certificateAuthority = "_ca"
)

var (
	_ CertificateAuthorityForge = (*customCA)(nil)
)

type CertificateAuthorityRepository interface {
	GetStoredCertificate(key string) (tls.Certificate, crypto.PrivateKey, error)
	StoreCertificate(key string, certificate tls.Certificate) error
	StorePrivateKey(key string, privateKey crypto.PrivateKey) error
}

type CertificateAuthorityForge interface {
	GenerateKey(host string) (tls.Certificate, error)
	ServeCA() (io.ReadSeeker, error)
}

type customCA struct {
	*CertificateAuthorityForgeOpts
	privateKey    crypto.PrivateKey
	caCertificate tls.Certificate
	repository    CertificateAuthorityRepository
	log           *log.Log
}

type CustomCAOpts struct {
	*CertificateAuthorityForgeOpts
	Repository CertificateAuthorityRepository
	Log        *log.Log
}

func NewCustomCA(customCAOpts *CustomCAOpts) (CertificateAuthorityForge, error) {
	caCertificate, caPrivateKey, err := customCAOpts.Repository.GetStoredCertificate(certificateAuthority)
	if err != nil {
		customCAOpts.Log.Info("no aldready stored certificate authority. creating a new one", zap.Error(err))
		caPrivateKey, err := generateECDSAPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("error in instantiating custom certificate authority: %w", err)
		}

		caCertificate, err = generateCA(caPrivateKey, customCAOpts.certificateOrganization, customCAOpts.certificateAuthorityCommonName, customCAOpts.certificateDuration)
		if err != nil {
			return nil, fmt.Errorf("error in instantiating custom certificate authority: %w", err)
		}

		err = customCAOpts.Repository.StoreCertificate(certificateAuthority, caCertificate)
		if err != nil {
			return nil, fmt.Errorf("storing certificate went ko: %w", err)
		}

		err = customCAOpts.Repository.StorePrivateKey(certificateAuthority, caPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("storing private key went ko: %w", err)
		}
	}

	return &customCA{
		CertificateAuthorityForgeOpts: customCAOpts.CertificateAuthorityForgeOpts,
		privateKey:                    caPrivateKey,
		caCertificate:                 caCertificate,
		repository:                    customCAOpts.Repository,
		log:                           customCAOpts.Log,
	}, nil
}

func (c *customCA) GenerateKey(host string) (tls.Certificate, error) {
	clientCertificate, _, err := c.repository.GetStoredCertificate(host)
	if err != nil {
		clientPrivateKey, err := generateECDSAPrivateKey()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error on creating client certificate for %s: %w", host, err)
		}
		clientCertificate, err = c.createCertificate(clientPrivateKey, []string{host})
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error on creating client certificate for %s: %w", host, err)
		}

		err = c.repository.StorePrivateKey(host, clientPrivateKey)
		if err != nil {
			c.log.Warn("client private key not stored", zap.String("key", host), zap.Error(err))
		}
		err = c.repository.StoreCertificate(host, clientCertificate)
		if err != nil {
			c.log.Warn("client certificate not stored", zap.String("key", host), zap.Error(err))
		}
	}

	return clientCertificate, nil
}

func (c *customCA) ServeCA() (io.ReadSeeker, error) {
	certificate, _, err := c.repository.GetStoredCertificate(certificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("service certificate authority error: %w", err)
	}
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	for _, item := range certificate.Certificate {

		pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: item})
	}

	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("service certificate authority error: failed to flush writer: %w", err)
	}

	return bytes.NewReader(b.Bytes()), nil
}

func (c *customCA) createCertificate(privateKey crypto.PrivateKey, hosts []string) (cert tls.Certificate, err error) {
	var x509ca *x509.Certificate

	if x509ca, err = x509.ParseCertificate(c.caCertificate.Certificate[0]); err != nil {
		return
	}
	hash := hashSorted(append(hosts, c.certificateSignerVersion, ":"+runtime.Version()))
	serial := new(big.Int)
	serial.SetBytes(hash)
	template := x509.Certificate{
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{c.certificateOrganization},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(c.certificateDuration),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	var (
		derBytes []byte
	)
	switch typeCastedPrivateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &typeCastedPrivateKey.PublicKey, c.caCertificate.PrivateKey)
	case *rsa.PrivateKey:
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &typeCastedPrivateKey.PublicKey, c.caCertificate.PrivateKey)
	default:
		return tls.Certificate{}, fmt.Errorf("private key type not supported: %+v", typeCastedPrivateKey)
	}
	if err != nil {
		return
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes, c.caCertificate.Certificate[0]},
		PrivateKey:  privateKey,
	}, nil
}

func generateECDSAPrivateKey() (crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error creating ecdsa private key: %w", err)
	}
	return privateKey, nil
}

func generateCA(privateKey crypto.PrivateKey, organization, caCommonName string, duration time.Duration) (tls.Certificate, error) {
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   caCommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	var (
		caCertBytes []byte
		err         error
	)
	switch typeCastedPrivateKey := privateKey.(type) {
	case *ecdsa.PrivateKey:
		caCertBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &typeCastedPrivateKey.PublicKey, typeCastedPrivateKey)
	case *rsa.PrivateKey:
		caCertBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &typeCastedPrivateKey.PublicKey, typeCastedPrivateKey)
	default:
		return tls.Certificate{}, fmt.Errorf("private key type not supported: %+v", typeCastedPrivateKey)
	}

	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}, nil
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}
