module scanoss.com/cryptography

go 1.19

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/golobby/config/v3 v3.3.1
	github.com/jmoiron/sqlx v1.3.4
	github.com/lib/pq v1.10.4
	github.com/mattn/go-sqlite3 v1.14.10
	github.com/package-url/packageurl-go v0.1.0
	github.com/scanoss/papi v0.2.0
	go.uber.org/zap v1.20.0
	google.golang.org/grpc v1.59.0
)

require (
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
)

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golobby/cast v1.3.0 // indirect
	github.com/golobby/dotenv v1.3.1 // indirect
	github.com/golobby/env/v2 v2.2.0 // indirect
	github.com/google/uuid v1.4.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Details of how to use the "replace" command for local development
// https://github.com/golang/go/wiki/Modules#when-should-i-use-the-replace-directive
// ie. replace github.com/scanoss/papi => ../papi
// require github.com/scanoss/papi v0.0.0-unpublished
