package log

import (
	"flag"
	"os"
)

var (
	logEnvironmentEnv, logEnvironmentEnvSet = os.LookupEnv("LOG_ENVIRONMENT")
	logEnvironment                          string
)

func init() {
	flag.StringVar(&logEnvironment, "log-environment", "", "Log environment")
}

func NewOptions() (*LogOpts, error) {
	if logEnvironmentEnvSet {
		logEnvironment = logEnvironmentEnv
	}

	return &LogOpts{
		LogEnvironment: logEnvironment,
	}, nil
}

type LogOpts struct {
	LogEnvironment string
}
