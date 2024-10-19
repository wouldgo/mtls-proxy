package pem_credential

import (
	"flag"
	"fmt"
	"os"
)

const (
	emptyStr = "-"
)

var (
	pemCredFolderEnv, pemCredFolderEnvSet = os.LookupEnv("PEM_CREDS_FOLDER")
	pemFullChainEnv, pemFullChainEnvSet   = os.LookupEnv("PEM_FULLCHAIN")
	pemPrivateKeyEnv, pemPrivateKeyEnvSet = os.LookupEnv("PEM_PRIVATE_KEY")

	pemCredFolder, pemFullChain, pemPrivateKey string
)

func init() {
	flag.StringVar(&pemCredFolder, "pem-cred-folder", emptyStr, "folder where to find credential for initialize mtls context")
	flag.StringVar(&pemFullChain, "pem-fullchain", emptyStr, "full chain filename inside the \"pem-creds-folder\"")
	flag.StringVar(&pemPrivateKey, "pem-private-key", emptyStr, "private key filename inside the \"pem-creds-folder\"")
}

type Opts struct {
	pemCredFolder, pemFullChain, pemPrivateKey string
}

func NewOpts() (*Opts, error) {
	if pemCredFolderEnvSet {
		pemCredFolder = pemCredFolderEnv
	}

	if pemFullChainEnvSet {
		pemFullChain = pemFullChainEnv
	}

	if pemPrivateKeyEnvSet {
		pemPrivateKey = pemPrivateKeyEnv
	}

	if pemCredFolder == emptyStr {
		return nil, fmt.Errorf("pem credential error: no credential folder provided")
	}

	if pemFullChain == emptyStr {
		return nil, fmt.Errorf("pem credential error: no fullchain file provided")
	}

	if pemPrivateKey == emptyStr {
		return nil, fmt.Errorf("pem credential error: no private key file provided")
	}

	return &Opts{
		pemCredFolder: pemCredFolder,
		pemFullChain:  pemFullChain,
		pemPrivateKey: pemPrivateKey,
	}, nil
}
