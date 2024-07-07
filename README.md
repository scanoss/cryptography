# SCANOSS Platform 2.0 Cryptography
Welcome to the Cryptography server for SCANOSS Platform 2.0

**Warning** Work In Progress **Warning**

## Repository Structure
This repository is made up of the following components:
* ?

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
go mod tidy -compat=1.20
```
https://mholt.github.io/json-to-go/
