module github.com/wouldgo/mtls-proxy

go 1.22

require (
	github.com/breml/rootcerts v0.2.18
	github.com/elazarl/goproxy v0.0.0-20240909085733-6741dbfc16a1
	github.com/jackc/pgx/v5 v5.7.1
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
	github.com/prometheus/client_golang v1.20.5
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.28.0
	golang.org/x/sync v0.8.0
)

replace gopkg.in/elazarl/goproxy.v1 v1.0.0-20180725130230-947c36da3153 => github.com/elazarl/goproxy v0.0.0-20240909085733-6741dbfc16a1

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
