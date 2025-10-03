// Package service provides cryptography service handlers and utilities for gRPC requests.
package handler

import (
	"context"
	"strconv"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	myconfig "scanoss.com/cryptography/pkg/config"
)

const (
	ResponseMessageSuccess = "Success"
	ResponseMessageError   = "Internal error occurred"
)

// setHTTPCodeOnTrailer sets the HTTP status code in the gRPC trailer metadata.
// This allows clients to determine the appropriate HTTP response code for the request.
func setHTTPCodeOnTrailer(ctx context.Context, s *zap.SugaredLogger, code int) {
	err := grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", strconv.Itoa(code)))
	if err != nil {
		s.Errorf("error setting x-http-code to trailer: %v\n", err)
	}
}

// telemetryRequestTime records the crypto algorithms request time to telemetry.
func telemetryRequestTime(ctx context.Context, config *myconfig.ServerConfig, requestStartTime time.Time) {
	if config.Telemetry.Enabled {
		elapsedTime := time.Since(requestStartTime).Milliseconds()     // Time taken to run the component name request
		oltpMetrics.cryptoAlgorithmsHistogram.Record(ctx, elapsedTime) // Record algorithm request time
	}
}
