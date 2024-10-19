package tls_management

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	customCAOptionsErrStr = "custom certificate authority options error: %w"
)

var (
	ignoreTLSCheckEnv, ignoreTLSCheckEnvSet = os.LookupEnv("IGNORE_TLS_CHECK")

	certificateDurationEnv, certificateDurationEnvSet                       = os.LookupEnv("CA_CERTIFICATE_DURATION")
	certificateOrganizationEnv, certificateOrganizationEnvSet               = os.LookupEnv("CA_ORGANIZATION")
	certificateAuthorityCommonNameEnv, certificateAuthorityCommonNameEnvSet = os.LookupEnv("CA_COMMON_NAME")
	certificateSignerVersionEnv, certificateSignerVersionEnvSet             = os.LookupEnv("CA_SIGNER_VERSION")

	ignoreTLSCheck bool

	certificateDuration                                                               time.Duration
	certificateOrganization, certificateAuthorityCommonName, certificateSignerVersion string
)

func init() {
	flag.BoolVar(&ignoreTLSCheck, "ignore-tls-check", true, "ignore TLS check")

	flag.DurationVar(&certificateDuration, "certificate-duration", 20*365*24*time.Hour, "certificate duration (default: 20 years)")

	flag.StringVar(&certificateOrganization, "certificate-organization", "proxy_org", "certificate organization name (default: proxy_org)")
	flag.StringVar(&certificateAuthorityCommonName, "certificate-authority-commonName", "proxy_ca", "certificate authority common name (default: proxy_ca)")
	flag.StringVar(&certificateSignerVersion, "certificate-signer-version", "proxy_1", "certificate signer version (default: proxy_1)")
}

func noValueFor(what string) error {
	return errors.New("no value provided " + what)
}

type Opts struct {
	IgnoreTLSCheck bool
}

type CertificateAuthorityForgeOpts struct {
	certificateDuration                                                               time.Duration
	certificateOrganization, certificateAuthorityCommonName, certificateSignerVersion string
}

func NewOptions() (*Opts, error) {
	if ignoreTLSCheckEnvSet {
		boolValue, err := strconv.ParseBool(ignoreTLSCheckEnv)
		if err != nil {
			return nil, fmt.Errorf(tlsOptionsErrStr, noValueFor("ignoreTLSCheckEnvSet"))
		}
		ignoreTLSCheck = boolValue
	}

	return &Opts{
		IgnoreTLSCheck: ignoreTLSCheck,
	}, nil
}

func NewCustomCAOptions() (*CertificateAuthorityForgeOpts, error) {
	if certificateDurationEnvSet {
		theDuration, err := time.ParseDuration(certificateDurationEnv)
		if err != nil {
			return nil, fmt.Errorf(customCAOptionsErrStr, err)
		}
		certificateDuration = theDuration
	}

	if certificateOrganizationEnvSet {
		certificateOrganization = certificateOrganizationEnv
	}

	if certificateAuthorityCommonNameEnvSet {
		certificateAuthorityCommonName = certificateAuthorityCommonNameEnv
	}

	if certificateSignerVersionEnvSet {
		certificateSignerVersion = certificateSignerVersionEnv
	}

	return &CertificateAuthorityForgeOpts{
		certificateDuration:            certificateDuration,
		certificateOrganization:        certificateOrganization,
		certificateAuthorityCommonName: certificateAuthorityCommonName,
		certificateSignerVersion:       certificateSignerVersion,
	}, nil
}
