package fs_certificates

import (
	"flag"
	"fmt"
	"os"
)

const (
	emptyStr = "-"
)

var (
	folderEnv, folderEnvSet = os.LookupEnv("CERTS_FOLDER")

	folder string
)

func init() {
	flag.StringVar(&folder, "certs-folder", emptyStr, "folder where to store the crafted certificates for connecting clients")
}

type Opts struct {
	folder string
}

func NewOpts() (*Opts, error) {
	if folderEnvSet {
		folder = folderEnv
	}

	if folder == emptyStr {
		return nil, fmt.Errorf("fs certificates error: no folder provided")
	}

	return &Opts{
		folder: folder,
	}, nil
}
