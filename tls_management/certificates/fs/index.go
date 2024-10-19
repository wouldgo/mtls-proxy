package fs_certificates

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"

	log "github.com/wouldgo/mtls-proxy/logging"
	"github.com/wouldgo/mtls-proxy/tls_management"
)

var (
	_ tls_management.CertificateAuthorityRepository = (*fileSystemCertificateRepository)(nil)
)

type fileSystemCertificateRepository struct {
	folder     string
	permission fs.FileMode
	lock       sync.RWMutex
}

type FileSystemCertificateRepositoryOpts struct {
	Log  *log.Log
	Opts *Opts
}

func NewFileSystemCertificateRepository(
	fileSystemCertificateRepositoryOpts *FileSystemCertificateRepositoryOpts,
) (tls_management.CertificateAuthorityRepository, error) {
	if strings.EqualFold(fileSystemCertificateRepositoryOpts.Opts.folder, "") {
		return nil, fmt.Errorf("folder is empty")
	}

	return &fileSystemCertificateRepository{
		folder: fileSystemCertificateRepositoryOpts.Opts.folder,
		permission: syscall.S_IRUSR | syscall.S_IWUSR | syscall.S_IXUSR |
			syscall.S_IRGRP | syscall.S_IXGRP,
		lock: sync.RWMutex{},
	}, nil
}

func (f *fileSystemCertificateRepository) GetStoredCertificate(key string) (tls.Certificate, crypto.PrivateKey, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()
	certificatePath := path.Join(f.folder, key, "certificate.pem")
	privateKeyPath := path.Join(f.folder, key, "private_key.pem")

	cert, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return cert, cert.PrivateKey, nil
}

func (f *fileSystemCertificateRepository) StoreCertificate(key string, certificate tls.Certificate) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	certificateFolder := path.Join(f.folder, key)
	err := os.MkdirAll(certificateFolder, f.permission)
	if err != nil {
		return err
	}

	certificatePath := path.Join(certificateFolder, "certificate.pem")
	certFile, err := os.Create(certificatePath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	for _, item := range certificate.Certificate {

		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: item})
	}
	return nil
}

func (f *fileSystemCertificateRepository) StorePrivateKey(key string, privateKey crypto.PrivateKey) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	privateKeyFolder := path.Join(f.folder, key)
	err = os.MkdirAll(privateKeyFolder, f.permission)
	if err != nil {
		return err
	}

	privateKeyPath := path.Join(privateKeyFolder, "private_key.pem")
	privateFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateFile.Close()
	pem.Encode(privateFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	return nil
}
