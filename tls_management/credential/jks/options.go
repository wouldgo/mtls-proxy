package jks_credential

import (
	"flag"
	"fmt"
	"os"
)

const (
	emptyStr = "-"
)

var (
	jksPathEnv, jksPathEnvSet         = os.LookupEnv("JKS_CERTIFICATE_PATH")
	jksEntryEnv, jksEntryEnvSet       = os.LookupEnv("JKS_CERTIFICATE_NAME")
	jksPasswordEnv, jksPasswordEnvSet = os.LookupEnv("JKS_CERTIFICATE_PASSWORD")

	jksPath, jksEntry, jksPassword string
)

func init() {
	flag.StringVar(&jksPath, "jks-file-path", emptyStr, "jks path")
	flag.StringVar(&jksEntry, "jks-entry", emptyStr, "jks entry name")
	flag.StringVar(&jksPassword, "jks-password", emptyStr, "jks password")
}

type Opts struct {
	jksPath, jksEntry, jksPassword string
}

func NewOpts() (*Opts, error) {
	if jksPathEnvSet {
		jksPath = jksPathEnv
	}

	if jksEntryEnvSet {
		jksEntry = jksEntryEnv
	}

	if jksPasswordEnvSet {
		jksPassword = jksPasswordEnv
	}

	if jksPath == emptyStr {
		return nil, fmt.Errorf("jks credential error: no path provided")
	}

	if jksEntry == emptyStr {
		return nil, fmt.Errorf("jks credential error: no entry provided")
	}

	if jksPassword == emptyStr {
		return nil, fmt.Errorf("jks credential error: no password provided")
	}

	return &Opts{
		jksPath:     jksPath,
		jksEntry:    jksEntry,
		jksPassword: jksPassword,
	}, nil
}
