package proxy

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"

	logging "log"

	"github.com/elazarl/goproxy"
	log "github.com/wouldgo/mtls-proxy/logging"
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
	proxy.NonproxyHandler = nonProxyHandler()

	toReturn := &Proxy{
		proxyHttpServer: proxy,
	}

	proxy.OnRequest().
		HandleConnect(opts.Handler)
	proxy.OnRequest().
		DoFunc(opts.ActionPerformer.Perform)

	return toReturn, nil
}

func (p *Proxy) Handler() http.Handler {
	return p.proxyHttpServer
}

func nonProxyHandler() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		resp := make(map[string]string)
		resp["message"] = "hello"
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)
	})
	return router
}
