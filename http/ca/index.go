package http_ca

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/tls_management"
	"go.uber.org/zap"
)

type CertificateAuthorityServer struct {
	router *http.ServeMux
}

type CertificateAuthorityServerOpts struct {
	Log                       *log.Log
	CertificateAuthorityForge tls_management.CertificateAuthorityForge
}

func NewCertificateAuthorityServer(certificateAuthorityServerOpts *CertificateAuthorityServerOpts) (*CertificateAuthorityServer, error) {
	toReturn := &CertificateAuthorityServer{
		router: http.NewServeMux(),
	}

	toReturn.router.HandleFunc("GET /ca", func(w http.ResponseWriter, r *http.Request) {
		certificateAuthorityServerOpts.Log.Info("called /ca url")
		reader, err := certificateAuthorityServerOpts.CertificateAuthorityForge.ServeCA()
		if err != nil {
			certificateAuthorityServerOpts.Log.Warn("/ca url in error", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			resp := make(map[string]string)
			resp["error"] = err.Error()
			jsonResp, err := json.Marshal(resp)
			if err != nil {
				certificateAuthorityServerOpts.Log.Fatal("Error happened in JSON marshal", zap.Error(err))
			}
			w.Write(jsonResp)
			return
		}

		http.ServeContent(w, r, "ca.pem", time.Now(), reader)
	})

	return toReturn, nil
}

func (c *CertificateAuthorityServer) Handler() http.Handler {
	return c.router
}
