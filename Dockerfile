FROM golang:1.25-bookworm AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go generate ./pkg/cmd/server.go
# cgo is required: the DuckDB driver used for the serving knowledge base is a
# cgo binding, so this cannot be a CGO_ENABLED=0 build.
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -ldflags="-w -s" -o ./scanoss-cryptography ./cmd/server

FROM build as test

COPY test-support/ldb.sh /app/ldb.sh

FROM debian:bookworm-slim

# The cgo binary links libstdc++ dynamically; ca-certificates keeps outbound TLS working.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/scanoss-cryptography /app/scanoss-cryptography

EXPOSE 50054

ENTRYPOINT ["./scanoss-cryptography"]
#CMD ["--help"]
