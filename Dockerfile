FROM golang:1.19 as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go generate ./pkg/cmd/server.go
RUN go build -o ./scanoss-cryptography ./cmd/server

FROM debian:buster-slim

WORKDIR /app
 
COPY --from=build /app/scanoss-cryptography /app/scanoss-cryptography

EXPOSE 50051

ENTRYPOINT ["./scanoss-cryptography"]
#CMD ["--help"]
