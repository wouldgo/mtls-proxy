package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/wouldgo/mtls-proxy/logging"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func isWebSocketRequest(r *http.Request) bool {
	var (
		isConnUpgrade = false
		isUpgradeWs   = false
	)
	for key, values := range r.Header {
		if key == "Connection" {
			for _, value := range values {
				for _, s := range strings.Split(value, ",") {
					if strings.EqualFold("upgrade", strings.TrimSpace(s)) {
						isConnUpgrade = true
					}
				}
			}
		}

		if key == "Upgrade" {
			for _, value := range values {
				for _, s := range strings.Split(value, ",") {
					if strings.EqualFold("websocket", strings.TrimSpace(s)) {
						isUpgradeWs = true
					}
				}
			}
		}
	}
	return isConnUpgrade && isUpgradeWs
}

func crossTheStreams(ctx context.Context, dst, src io.ReadWriter) error {
	g, _ := errgroup.WithContext(ctx)

	g.Go(func() error {
		_, err := io.Copy(dst, src)
		return err
	})
	g.Go(func() error {
		_, err := io.Copy(src, dst)
		return err
	})

	err := g.Wait()
	if err != nil {
		return fmt.Errorf("crossing the streams in error: %w", err)
	}
	return nil
}

type websocketHandler struct {
	logger *log.Log
}

func (p *websocketHandler) websocketHandshake(req *http.Request, targetSiteConn io.ReadWriter, clientConn io.ReadWriter) error {
	// write handshake request to target
	err := req.Write(targetSiteConn)
	if err != nil {
		p.logger.Warn("error writing upgrade request", zap.Error(err))
		return err
	}

	targetTLSReader := bufio.NewReader(targetSiteConn)

	// Read handshake response from target
	resp, err := http.ReadResponse(targetTLSReader, req)
	if err != nil {
		p.logger.Warn("error reading handhsake response", zap.Error(err))
		return err
	}

	// Proxy handshake back to client
	err = resp.Write(clientConn)
	if err != nil {
		p.logger.Warn("error writing handshake response", zap.Error(err))
		return err
	}
	return nil
}
