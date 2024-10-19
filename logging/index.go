package log

import (
	"context"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zapio"
	"golang.org/x/sync/errgroup"
)

type Log struct {
	*zap.Logger

	writerLock  sync.Mutex
	innerWriter *zapio.Writer
	writerLvl   zapcore.Level
}

func NewLog(opts *LogOpts) (*Log, error) {
	var config zap.Config
	var level zapcore.Level
	if strings.EqualFold(opts.LogEnvironment, "production") {
		config = zap.NewProductionConfig()
		level = zapcore.ErrorLevel
	} else {
		config = zap.NewDevelopmentConfig()
		level = zapcore.DebugLevel
	}

	config.Encoding = "console"
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stdout"}

	log, _ := config.Build()

	return &Log{
		Logger:     log,
		writerLvl:  level,
		writerLock: sync.Mutex{},
	}, nil
}

func (l *Log) Writer() *zapio.Writer {
	l.writerLock.Lock()
	defer l.writerLock.Unlock()
	if l.innerWriter == nil {

		l.innerWriter = &zapio.Writer{
			Log:   l.Logger,
			Level: l.writerLvl,
		}
	}
	return l.innerWriter
}

func (l *Log) Close(ctx context.Context) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		if l.innerWriter != nil {
			return l.innerWriter.Close()
		}
		return nil
	})

	return g.Wait()
}
