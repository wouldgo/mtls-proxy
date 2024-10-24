package pg_credential

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/wouldgo/mtls-proxy/tls_management"
	"go.uber.org/zap"
)

var (
	_ tls_management.CredentialRetriver = (*pgCredentialRetriver)(nil)
)

const query = `
SELECT alias.%s AS %s
FROM %s AS alias
`

type pgCredentialRetriver struct {
	log   *zap.Logger
	conn  *pgx.Conn
	query string
}

type PgCredentialRetriverOpts struct {
	Log  *zap.Logger
	Opts *Opts
}

func NewPgCredendialRetriver(
	ctx context.Context,
	pgMTLSCredentialRetriverOpts *PgCredentialRetriverOpts,
) (tls_management.CredentialRetriver, error) {
	ctx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()

	connectionStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s",
		pgMTLSCredentialRetriverOpts.Opts.username,
		pgMTLSCredentialRetriverOpts.Opts.password,
		pgMTLSCredentialRetriverOpts.Opts.host,
		pgMTLSCredentialRetriverOpts.Opts.port,
		pgMTLSCredentialRetriverOpts.Opts.database,
	)

	conn, err := pgx.Connect(ctx, connectionStr)
	if err != nil {
		return nil, fmt.Errorf("pg credential retriver error: %w", err)
	}

	query := fmt.Sprintf(
		query,
		pgMTLSCredentialRetriverOpts.Opts.column,
		pgMTLSCredentialRetriverOpts.Opts.column,
		pgMTLSCredentialRetriverOpts.Opts.table,
	)

	return &pgCredentialRetriver{
		log:   pgMTLSCredentialRetriverOpts.Log,
		conn:  conn,
		query: query,
	}, nil
}

func (p *pgCredentialRetriver) Get(ctx context.Context) (*tls.Certificate, *x509.CertPool, error) {
	p.log.Info("getting credential")
	_, err := p.get(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("pg mtls credential retriever error: %w", err)
	}

	panic("hic sunt leones")
}

func (p *pgCredentialRetriver) Close(ctx context.Context) error {
	p.log.Info("closing pg mtls credential retriever")
	return p.conn.Close(ctx)
}

func (p *pgCredentialRetriver) get(ctx context.Context) ([]byte, error) {
	p.log.Info("trying getting credential")
	var content []byte
	err := p.conn.QueryRow(ctx, p.query).Scan(&content)

	return content, err
}
