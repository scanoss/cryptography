module scanoss.com/cryptography

go 1.25.0

require (
	github.com/Masterminds/semver/v3 v3.4.0
	github.com/golobby/config/v3 v3.4.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/lib/pq v1.12.3
	github.com/scanoss/go-grpc-helper v0.15.1
	github.com/scanoss/go-purl-helper v0.3.0
	github.com/scanoss/papi v0.41.0
	github.com/scanoss/zap-logging-helper v0.4.0
	github.com/stretchr/testify v1.11.1
	go.opentelemetry.io/otel v1.43.0
	go.opentelemetry.io/otel/metric v1.43.0
	go.uber.org/zap v1.27.1
	google.golang.org/grpc v1.80.0
	modernc.org/sqlite v1.48.2
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/package-url/packageurl-go v0.1.5
	github.com/phuslu/iploc v1.0.20250430 // indirect
	github.com/scanoss/ipfilter/v2 v2.0.2 // indirect
	github.com/tomasen/realip v0.0.0-20180522021738-f0c99a92ddce // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.65.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.40.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.40.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.40.0 // indirect
	go.opentelemetry.io/otel/sdk v1.40.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260209200024-4cfbd4190f57
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260209200024-4cfbd4190f57 // indirect
)

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golobby/cast v1.3.3 // indirect
	github.com/golobby/dotenv v1.3.2 // indirect
	github.com/golobby/env/v2 v2.2.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// Details of how to use the "replace" command for local development
// https://github.com/golang/go/wiki/Modules#when-should-i-use-the-replace-directive
// ie. replace github.com/scanoss/papi => ../papi
//replace github.com/scanoss/papi => ../papi

// require github.com/scanoss/papi v0.0.0-unpublished
