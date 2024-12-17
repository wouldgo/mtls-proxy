package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"

	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
)

var (
	okHTTPResponse = []byte("HTTP/1.0 200 OK\r\n\r\n")
)

type Performer interface {
	PerformHTTP(req *http.Request) *http.Response
	PerformWS(req *http.Request) (net.Conn, error)
}

type Proxy struct {
	context   context.Context
	logger    *log.Log
	tlsConfig *tls.Config
	transport *http.Transport

	handler          TLSHandle
	actionPerformer  Performer
	websocketHandler *websocketHandler
}

type ProxyConfig struct {
	Context         context.Context
	Logger          *log.Log
	TlsConfig       *tls.Config
	Handler         HttpsHandler
	ActionPerformer Performer
}

func NewProxy(opts *ProxyConfig) (*Proxy, error) {
	toReturn := &Proxy{
		context:   opts.Context,
		logger:    opts.Logger,
		tlsConfig: opts.TlsConfig,
		transport: &http.Transport{
			TLSClientConfig: opts.TlsConfig,
			Proxy:           http.ProxyFromEnvironment,
		},

		handler:         opts.Handler.HandleConnect(),
		actionPerformer: opts.ActionPerformer,
		websocketHandler: &websocketHandler{
			logger: opts.Logger,
		},
	}

	return toReturn, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		err error
	)
	if r.Method == "CONNECT" {
		p.logger.Info("proxing https connection")
		err = p.handleHttps(w, r)
	} else {
		p.logger.Info("proxing http connection")
		err = p.handleHttp(w, r)
	}

	if err != nil {
		w.WriteHeader(http.StatusPreconditionFailed)
		w.Header().Set("Content-type", "plain/text")
		w.Write([]byte(err.Error()))
	}
}

func (p *Proxy) ServeConn(conn net.Conn) error {
	connReplay, err := newConnRewinder(conn)
	if err != nil {
		return fmt.Errorf("error creating net.Conn rewinder wrapper: %w", err)
	}
	remoteHost, err := getServerName(connReplay)
	if err != nil {
		return fmt.Errorf("error extracting hostname: %w", err)
	}
	p.logger.Debug("trasparent proxying", zap.String("remoteHost", remoteHost))

	newConn, err := connReplay.Rewind()
	if err != nil {
		return fmt.Errorf("net.Conn rewind error: %w", err)
	}
	return p.handleTlsConn(remoteHost, newConn)
}

func (p *Proxy) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		p.logger.Info("arrived tcp connection", zap.Any("remote_addr", conn.RemoteAddr()), zap.Any("local_addr", conn.LocalAddr()))
		if err != nil {
			return fmt.Errorf("transparent proxy accept in error: %w", err)
		}
		go func(connection net.Conn) {
			if err := p.ServeConn(connection); err != nil {
				p.logger.Error("transparent proxy error", zap.Error(err))
			}
		}(conn)
	}
}

func (p *Proxy) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

func (p *Proxy) handleHttps(w http.ResponseWriter, r *http.Request) error {
	hij, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("http connection does not support hijacking")
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		return fmt.Errorf("cannot hijack connection: %w", e)
	}
	fqdn := r.URL.Host

	p.logger.Debug("http/s proxying", zap.String("fqdn", fqdn))
	proxyClient.Write(okHTTPResponse)
	p.logger.Info("replied to proxied client CONNECT with an 200 OK", zap.String("fqdn", fqdn))
	return p.handleTlsConn(fqdn, proxyClient)
}

func (p *Proxy) handleHttp(w http.ResponseWriter, r *http.Request) error {
	hij, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("http connection does not support hijacking")
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		return fmt.Errorf("cannot hijack connection: %w", e)
	}

	err := p.handleReq(r, proxyClient)
	if err != nil {
		return fmt.Errorf("handling proxy request in error: %w", err)
	}
	return nil
}

func (p *Proxy) handleTlsConn(fqdn string, proxyClient net.Conn) error {
	p.logger.Debug("creating tls config", zap.String("fqdn", fqdn))
	tlsConfig, err := p.handler(fqdn)
	if err != nil {
		return fmt.Errorf("error on tls handling: %w", err)
	}

	go func() {
		//TODO: cache connections to the remote website
		p.logger.Info("proxing client in tls", zap.String("fqdn", fqdn),
			zap.Any("remote_addr", proxyClient.RemoteAddr()), zap.Any("local_addr", proxyClient.LocalAddr()))
		rawClientTls := tls.Server(proxyClient, tlsConfig)
		// XXX leak on not closing proxyClient?
		// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
		defer func() {
			p.logger.Info("closing tls connection")
			err := proxyClient.Close()
			if err != nil {
				p.logger.Error("closing proxing client in error", zap.Error(err))
			}

			err = rawClientTls.Close()
			if err != nil {
				p.logger.Error("closing local tls connection client in error", zap.Error(err))
			}
		}()

		if err := rawClientTls.HandshakeContext(context.TODO()); err != nil {
			p.logger.Warn("cannot tls handshake for proxied client", zap.String("fqdn", fqdn),
				zap.Any("remote_addr", proxyClient.RemoteAddr()), zap.Any("local_addr", proxyClient.LocalAddr()),
				zap.Error(err))
			return
		}
		clientTlsReader := bufio.NewReader(rawClientTls)

		for {
			req, err := http.ReadRequest(clientTlsReader)
			if err == io.EOF {
				p.logger.Info("tls proxied http connection ended", zap.String("fqdn", fqdn),
					zap.Any("remote_addr", proxyClient.RemoteAddr()), zap.Any("local_addr", proxyClient.LocalAddr()))
				return
			} else if err != nil {
				p.logger.Warn("tls proxied http connection reading in error", zap.String("fqdn", fqdn),
					zap.Any("remote_addr", proxyClient.RemoteAddr()), zap.Any("local_addr", proxyClient.LocalAddr()),
					zap.Error(err))
				return
			}

			err = p.handleReq(req, rawClientTls)
			if err != nil {
				p.logger.Error("tls proxied http request handling in error", zap.String("fqdn", fqdn),
					zap.Any("remote_addr", proxyClient.RemoteAddr()), zap.Any("local_addr", proxyClient.LocalAddr()),
					zap.Error(err))
				return
			}
		}
	}()
	return nil
}

func (p *Proxy) handleReq(req *http.Request, clientConn io.ReadWriter) error {
	req.URL.Host = req.Host
	if req.URL.Port() == "" {
		req.URL.Host = net.JoinHostPort(req.URL.Host, "443")
	}

	if isWebSocketRequest(req) {
		p.logger.Info("websocket request", zap.Any("request", req))
		req.URL.Scheme = "wss"

		peerConn, err := p.actionPerformer.PerformWS(req)
		if err != nil {
			return fmt.Errorf("websocket connection handling in error: %w", err)
		}
		defer peerConn.Close()

		if err := p.websocketHandler.websocketHandshake(req, peerConn, clientConn); err != nil {
			return fmt.Errorf("websocket handshake in error: %w", err)
		}

		err = crossTheStreams(p.context, peerConn, clientConn)
		if err != nil {
			return fmt.Errorf("websocket connection in error: %w", err)
		}
	}
	req.URL.Scheme = "https"

	var b bytes.Buffer
	_ = req.Write(&b)
	stringyRequest := b.String()
	p.logger.Debug("https request", zap.Any("request", stringyRequest))

	httpResponse := p.actionPerformer.PerformHTTP(req)
	if httpResponse == nil {
		// explicitly discard request body to avoid data races in certain RoundTripper implementations
		// see https://github.com/golang/go/issues/61596#issuecomment-1652345131
		defer req.Body.Close()

		var err error
		if httpResponse, err = p.transport.RoundTrip(req); err != nil {

			return fmt.Errorf("tls response from server in error: %w", err)
		}

		// if req.Method == "PRI" {
		// 	// Handle HTTP/2 connections.

		// 	// NOTE: As of 1.22, golang's http module will not recognize or
		// 	// parse the HTTP Body for PRI requests. This leaves the body of
		// 	// the http2.ClientPreface ("SM\r\n\r\n") on the wire which we need
		// 	// to clear before setting up the connection.
		// 	_, err := clientTlsReader.Discard(6)
		// 	if err != nil {
		// 		ctx.Warnf("Failed to process HTTP2 client preface: %v", err)
		// 		return
		// 	}
		// 	if !proxy.AllowHTTP2 {
		// 		ctx.Warnf("HTTP2 connection failed: disallowed")
		// 		return
		// 	}
		// 	tr := H2Transport{clientTlsReader, rawClientTls, tlsConfig.Clone(), host}
		// 	if _, err := tr.RoundTrip(req); err != nil {
		// 		ctx.Warnf("HTTP2 connection failed: %v", err)
		// 	} else {
		// 		ctx.Logf("Exiting on EOF")
		// 	}
		// 	return
		// }
	}
	defer httpResponse.Body.Close()

	p.logger.Debug("https response", zap.Any("request", stringyRequest), zap.String("status", httpResponse.Status))

	// always use 1.1 to support chunked encoding
	if _, err := io.WriteString(clientConn, "HTTP/1.1"+" "+httpResponse.Status+"\r\n"); err != nil {
		return fmt.Errorf("cannot write tls response HTTP status to proxy client: %w", err)
	}

	if httpResponse.Request.Method != "HEAD" { // don't change Content-Length for HEAD request
		httpResponse.Header.Del("Content-Length")
		httpResponse.Header.Set("Transfer-Encoding", "chunked")
	}
	// Force connection close otherwise chrome will keep CONNECT tunnel open forever
	httpResponse.Header.Set("Connection", "close")

	if err := httpResponse.Header.Write(clientConn); err != nil {
		return fmt.Errorf("cannot write tls response header to client: %w", err)
	}
	if _, err := io.WriteString(clientConn, "\r\n"); err != nil {
		return fmt.Errorf("cannot write tls response header end to client: %w", err)
	}

	if httpResponse.Request.Method != "HEAD" { // Don't write out a response body for HEAD request
		chunked := newChunkedWriter(clientConn)
		if _, err := io.Copy(chunked, httpResponse.Body); err != nil {
			return fmt.Errorf("cannot write tls response body to client: %w", err)
		}
		if err := chunked.Close(); err != nil {
			return fmt.Errorf("cannot write tls chunked EOF to client: %w", err)
		}
		if _, err := io.WriteString(clientConn, "\r\n"); err != nil {
			return fmt.Errorf("cannot write tls response chunked trailer from mitm'd client: %w", err)
		}
	}
	return nil
}
