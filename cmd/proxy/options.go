package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/tls_management"
	fs_certificates "github.com/wouldgo/mtls-proxy/tls_management/certificates/fs"
	pem_credential "github.com/wouldgo/mtls-proxy/tls_management/credential/pem"
)

const (
	optionsErrStr = "options error: %w"
)

var (
	transparentProxyNetworkEnv, transparentProxyNetworkEnvSet = os.LookupEnv("TRANSPARENT_PROXY_NETWORK")
	transparentProxyAddrEnv, transparentProxyAddrEnvSet       = os.LookupEnv("TRANSPARENT_PROXY_ADDR")
	proxyListenAddrEnv, proxyListenAddrEnvSet                 = os.LookupEnv("PROXY_LISTEN_ADDR")
	caServerAddrEnv, caServerAddrEnvSet                       = os.LookupEnv("CA_LISTEN_ADDR")
	metricsServerAddrEnv, metricsServerAddrEnvSet             = os.LookupEnv("METRICS_LISTEN_ADDR")

	transparentProxyNetwork, transparentProxyAddr, proxyListenAddr, caServerAddr, metricsServerAddr string
)

func init() {
	flag.StringVar(&transparentProxyNetwork, "transparent-proxy-network", "tcp", "transparent proxy network")
	flag.StringVar(&transparentProxyAddr, "transparent-proxy-addr", ":3000", "transparent proxy address")
	flag.StringVar(&proxyListenAddr, "proxy-listen-addr", ":3001", "proxy listen address")
	flag.StringVar(&caServerAddr, "ca-listen-addr", ":3002", "certificate authority server listen address")
	flag.StringVar(&metricsServerAddr, "metrics-listen-addr", ":3003", "metrics server listen address")
}

type options struct {
	tls *tls_management.Opts
	log *log.LogOpts
	ca  *tls_management.CertificateAuthorityForgeOpts

	pemCred *pem_credential.Opts
	fsCerts *fs_certificates.Opts

	transparentProxyNetwork, transparentProxyAddr, proxyAddr, caServerAddr, metricsServerAddr string
}

func newOptions() (*options, error) {
	logs, err := log.NewOptions()
	if err != nil {
		return nil, fmt.Errorf(optionsErrStr, err)
	}

	otps, err := tls_management.NewOptions()
	if err != nil {
		return nil, fmt.Errorf(optionsErrStr, err)
	}

	caOptions, err := tls_management.NewCustomCAOptions()
	if err != nil {
		return nil, fmt.Errorf(optionsErrStr, err)
	}

	pemCredOpts, err := pem_credential.NewOpts()
	if err != nil {
		return nil, fmt.Errorf(optionsErrStr, err)
	}

	fsCertsOpts, err := fs_certificates.NewOpts()
	if err != nil {
		return nil, fmt.Errorf(optionsErrStr, err)
	}

	if transparentProxyNetworkEnvSet {
		transparentProxyNetwork = transparentProxyNetworkEnv
	}

	if transparentProxyAddrEnvSet {
		transparentProxyAddr = transparentProxyAddrEnv
	}

	if proxyListenAddrEnvSet {
		proxyListenAddr = proxyListenAddrEnv
	}

	if caServerAddrEnvSet {
		caServerAddr = caServerAddrEnv
	}

	if metricsServerAddrEnvSet {
		metricsServerAddr = metricsServerAddrEnv
	}

	return &options{
		log: logs,
		tls: otps,
		ca:  caOptions,

		pemCred: pemCredOpts,
		fsCerts: fsCertsOpts,

		transparentProxyNetwork: transparentProxyNetwork,
		transparentProxyAddr:    transparentProxyAddr,
		proxyAddr:               proxyListenAddr,
		caServerAddr:            caServerAddr,
		metricsServerAddr:       metricsServerAddr,
	}, nil
}
