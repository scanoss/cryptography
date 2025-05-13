# SCANOSS Platform 2.0 Cryptography Service
Welcome to the Cryptography server for SCANOSS Platform 2.0
A specialized service providing methods for Export Control tasks in software analysis. This service helps identify and track cryptographic algorithms and security-related components in software packages.

## Key Features

### Cryptographic Algorithm Detection
- **Exact Version Analysis**: Find cryptographic algorithms in specific package versions using PURL
- **Version Range Analysis**: Detect cryptographic algorithms across version ranges (Semver compliant)
- **Coverage Analysis**: Identify versions containing cryptographic algorithms that may go undetected within specified version ranges

### Security Component Analysis
- Detect usage patterns of:
  - Libraries
  - Frameworks
  - SDKs
  - Security Protocols

## Service Access

The service is accessible through:
- gRPC methods (primary)
- REST API (via gateway)

For detailed service definitions, see our [PAPI Documentation](https://github.com/scanos/papi)

## Database Support

Compatible with multiple database systems including:
- SQLite
- PostgreSQL
- Other SQL-compatible databases

Database connection can be configured via:
- Environment file (.env)
- Configuration file (.json)

## Data Collection

For optimal data gathering and table population, we recommend using [minr](https://github.com/scanoss/minr).

## Configuration

Environmental variables are fed in this order:

dot-env --> env.json -->  Actual Environment Variable

These are the supported configuration arguments:

```
APP_NAME="SCANOSS Cryptography Server"
APP_PORT=50054
APP_MODE=dev
APP_DEBUG=false
DB_DSN="./test-support/sqlite/scanoss.db?cache=shared&mode=memory"
```

## Docker Environment

The Cryptography server can be deployed as a Docker container.

Adjust configurations by updating an .env file in the root of this repository.


### How to build

You can build your own image of the SCANOSS Cryptography Server with the ```docker build``` command as follows.

```bash
make ghcr_build
```


### How to run

Run the SCANOSS Cryptography Server Docker image by specifying the environmental file to be used with the ```--env-file``` argument. 

You may also need to expose the ```APP_PORT``` on a given ```interface:port``` with the ```-p``` argument.

```bash
docker run -it -v "$(pwd)":"$(pwd)" -p 50054:50054 ghcr.io/scanoss/scanoss-cryptography-api -json-config $(pwd)/config/app-config-docker-local-dev.json -debug
```

## Development

To run locally on your desktop, please use the following command:

```shell
go run cmd/server/main.go -json-config config/app-config-dev.json -debug
```

After changing a Cryptography version, please run the following command:
```shell
go mod tidy -compat=1.24
```
https://mholt.github.io/json-to-go/

## License 

GPL-2.0-or-later

Copyright (C) 2025 SCANOSS.COM