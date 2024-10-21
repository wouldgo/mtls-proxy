package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"regexp"
	"strings"

	logging "log"

	"github.com/elazarl/goproxy"
	log "github.com/wouldgo/mtls-proxy/logging"
	"golang.org/x/sync/errgroup"
)

var (
	unathorizedReader = strings.NewReader("Not Authorized")
)

type Proxy struct {
	proxyHttpServer *goproxy.ProxyHttpServer
}

type ProxyConfig struct {
	Logger          *log.Log
	TlsConfig       *tls.Config
	Handler         goproxy.HttpsHandler
	ActionPerformer Performer
	Verbose         bool
}

func NewProxy(opts *ProxyConfig) (*Proxy, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = opts.Verbose

	proxy.Logger = logging.New(opts.Logger.Writer(), "", 0)

	toReturn := &Proxy{
		proxyHttpServer: proxy,
	}

	rule := goproxy.UrlMatches(regexp.MustCompile(".*"))
	proxy.OnRequest(rule).
		HandleConnect(opts.Handler)
	proxy.OnRequest(rule).
		DoFunc(opts.ActionPerformer.Perform)

	return toReturn, nil
}

func (p *Proxy) Listen(ctx context.Context, addr string) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {

		return http.ListenAndServe(addr, p.proxyHttpServer)
	})

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (p *Proxy) Close(ctx context.Context) error {
	return nil
}
