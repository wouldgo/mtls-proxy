package pg_credential

import (
	"flag"
	"fmt"
	"os"
)

const (
	emptyStr = "-"
)

var (
	hostEnv, hostEnvSet         = os.LookupEnv("PG_HOST")
	portEnv, portEnvSet         = os.LookupEnv("PG_PORT")
	usernameEnv, usernameEnvSet = os.LookupEnv("PG_USERNAME")
	passwordEnv, passwordEnvSet = os.LookupEnv("PG_PASSWORD")
	databaseEnv, databaseEnvSet = os.LookupEnv("PG_DATABASE")
	tableEnv, tableEnvSet       = os.LookupEnv("PG_TABLE")
	columnEnv, columnEnvSet     = os.LookupEnv("PG_COLUMN")

	host, port, username, password,
	database, table, column string
)

func init() {

	flag.StringVar(&host, "pg-host", emptyStr, "pg host where download credential")
	flag.StringVar(&port, "pg-port", emptyStr, "pg port where download credential")
	flag.StringVar(&username, "pg-username", emptyStr, "pg username where download credential")
	flag.StringVar(&password, "pg-password", emptyStr, "pg password where download credential")
	flag.StringVar(&database, "pg-database", emptyStr, "pg database where download credential")
	flag.StringVar(&table, "pg-table", emptyStr, "pg table where download credential")
	flag.StringVar(&column, "pg-column", emptyStr, "pg column where download credential")
}

type Opts struct {
	host, port, username, password,
	database, table, column string
}

func NewOpts() (*Opts, error) {
	if hostEnvSet {
		host = hostEnv
	}
	if portEnvSet {
		port = portEnv
	}
	if usernameEnvSet {
		username = usernameEnv
	}
	if passwordEnvSet {
		password = passwordEnv
	}
	if databaseEnvSet {
		database = databaseEnv
	}
	if tableEnvSet {
		table = tableEnv
	}
	if columnEnvSet {
		column = columnEnv
	}

	if host == emptyStr {
		return nil, fmt.Errorf("pg credential error: no host provided")
	}
	if port == emptyStr {
		return nil, fmt.Errorf("pg credential error: no port provided")
	}
	if username == emptyStr {
		return nil, fmt.Errorf("pg credential error: no username provided")
	}
	if password == emptyStr {
		return nil, fmt.Errorf("pg credential error: no password provided")
	}
	if database == emptyStr {
		return nil, fmt.Errorf("pg credential error: no database provided")
	}
	if table == emptyStr {
		return nil, fmt.Errorf("pg credential error: no table provided")
	}
	if column == emptyStr {
		return nil, fmt.Errorf("pg credential error: no column provided")
	}

	return &Opts{
		host:     host,
		port:     port,
		username: username,
		password: password,
		database: database,
		table:    table,
		column:   column,
	}, nil
}
