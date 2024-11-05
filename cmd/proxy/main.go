package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/breml/rootcerts"
	http_ca "github.com/wouldgo/mtls-proxy/http/ca"
	http_metrics "github.com/wouldgo/mtls-proxy/http/metrics"
	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/proxy"
	"github.com/wouldgo/mtls-proxy/tier_2"
	"github.com/wouldgo/mtls-proxy/tls_management"
	fs_repository "github.com/wouldgo/mtls-proxy/tls_management/certificates/fs"
	pem_credential "github.com/wouldgo/mtls-proxy/tls_management/credential/pem"
	"go.uber.org/zap"
)

func main() {
	flag.Parse()

	options, err := newOptions()
	if err != nil {
		panic(err)
	}

	logger, err := log.NewLog(options.log)
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	logger.Info("waiting for SIGTERM or SIGINT")
	defer stop()

	config, err := tlsConfig(
		ctx,
		logger,
		options,
	)
	if err != nil {
		logger.Fatal("starup error", zap.Error(err))
	}

	handler, certificateAuthorityForge, err := handler(
		logger,
		options,
	)
	if err != nil {
		logger.Fatal("starup error", zap.Error(err))
	}

	performer, err := tier_2.NewMtlsPerformer(&tier_2.MTLSPerformerOpts{
		Log:       logger,
		TlsConfig: config,
	})
	if err != nil {
		logger.Fatal("starup error", zap.Error(err))
	}

	theProxy, err := proxy.NewProxy(&proxy.ProxyConfig{
		Logger:          logger,
		TlsConfig:       config,
		Handler:         handler,
		ActionPerformer: performer,
	})
	if err != nil {
		logger.Fatal("starup error", zap.Error(err))
	}

	caSever, err := http_ca.NewCertificateAuthorityServer(&http_ca.CertificateAuthorityServerOpts{
		Log:                       logger,
		CertificateAuthorityForge: certificateAuthorityForge,
	})
	if err != nil {
		logger.Fatal("startup error", zap.Error(err))
	}

	metricsServer, err := http_metrics.NewMetricsServer(&http_metrics.MetricsServerOpts{
		Log: logger,
	})
	if err != nil {
		logger.Fatal("startup error", zap.Error(err))
	}

	go func() {
		logger.Info("staring transparent proxy", zap.String("protocol", options.transparentProxyNetwork), zap.String("addr", options.transparentProxyAddr))
		err := theProxy.ListenAndServe(options.transparentProxyNetwork, options.transparentProxyAddr)
		if err != nil {
			logger.Error("transparent proxy closed error", zap.Error(err))
		} else {
			logger.Info("transparent proxy closed")
		}
	}()

	go func() {
		logger.Info("starting http/s proxy", zap.String("addr", options.proxyAddr))
		err := http.ListenAndServe(options.proxyAddr, theProxy)
		if err != nil {
			logger.Error("proxy closed error", zap.Error(err))
		} else {
			logger.Info("proxy closed")
		}
	}()

	go func() {
		logger.Info("starting certificate authority server", zap.String("addr", options.caServerAddr))
		err := http.ListenAndServe(options.caServerAddr, caSever.Handler())
		if err != nil {
			logger.Error("certificate authority closed error", zap.Error(err))
		} else {
			logger.Info("certificate authority server closed")
		}
	}()

	go func() {
		logger.Info("metrics server", zap.String("addr", options.metricsServerAddr))
		err := http.ListenAndServe(options.metricsServerAddr, metricsServer.Handler())
		if err != nil {
			logger.Error("metrics server closed error", zap.Error(err))
		} else {
			logger.Info("metrics server closed")
		}
	}()

	<-ctx.Done()

	ctx, stop = context.WithTimeout(context.Background(), 5*time.Second)
	logger.Info("terminating")
	defer stop()

	//XXX tearing down eventual connections

	logger.Info("bye")
	err = logger.Close(ctx)
	if err != nil {
		panic(err)
	}
}

func tlsConfig(
	ctx context.Context,
	logger *log.Log,
	options *options,
) (*tls.Config, error) {
	retriver, err := pem_credential.NewPemCredentialRetriver(&pem_credential.PemCredentialRetriverOpts{
		Log:  logger,
		Opts: options.pemCred,
	})
	if err != nil {
		return nil, fmt.Errorf("tls config error: %w", err)
	}

	tlsChecker, err := tls_management.NewChecker(&tls_management.CheckerOpts{
		Logger:         logger,
		IgnoreTLSCheck: options.tls.IgnoreTLSCheck,
	})
	if err != nil {
		return nil, fmt.Errorf("tls config configuration error: %w", err)
	}

	tlsConfig, err := options.tls.TlsConfig(ctx, &tls_management.TLSCheckerOpts{
		Logger:             logger,
		TLSChecker:         tlsChecker,
		CredentialRetriver: retriver,
	})
	if err != nil {
		return nil, fmt.Errorf("tls config configuration error: %w", err)
	}
	return tlsConfig, nil
}

func handler(logger *log.Log, options *options) (proxy.HttpsHandler, tls_management.CertificateAuthorityForge, error) {
	repository, err := fs_repository.NewFileSystemCertificateRepository(&fs_repository.FileSystemCertificateRepositoryOpts{
		Log:  logger,
		Opts: options.fsCerts,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("handler configuration error: %w", err)
	}

	certificateAuthorityForge, err := tls_management.NewCustomCA(&tls_management.CustomCAOpts{
		CertificateAuthorityForgeOpts: options.ca,
		Repository:                    repository,
		Log:                           logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("handler configuration error: %w", err)
	}

	handler, err := proxy.NewMitmHandler(&proxy.MitmHandlerOpts{
		CertificateAuthorityForge: certificateAuthorityForge,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("handler configuration error: %w", err)
	}
	return handler, certificateAuthorityForge, nil
}
