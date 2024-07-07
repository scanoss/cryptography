FROM golang:1.20 as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go generate ./pkg/cmd/server.go
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-w -s" -o ./scanoss-cryptography ./cmd/server \

FROM build as test

COPY test-support/ldb.sh /app/ldb.sh

FROM debian:buster-slim

WORKDIR /app
 
COPY --from=build /app/scanoss-cryptography /app/scanoss-cryptography

EXPOSE 50054

ENTRYPOINT ["./scanoss-cryptography"]
#CMD ["--help"]
