// Package service provides cryptography service handlers and utilities for gRPC requests.
package handlers

import (
	"context"
	"time"

	myconfig "scanoss.com/cryptography/pkg/config"
)

const (
	ResponseMessageSuccess = "Success"
	ResponseMessageError   = "Internal error occurred"
)

// telemetryRequestTime records the crypto algorithms request time to telemetry.
func telemetryRequestTime(ctx context.Context, config *myconfig.ServerConfig, requestStartTime time.Time) {
	if config.Telemetry.Enabled {
		elapsedTime := time.Since(requestStartTime).Milliseconds()     // Time taken to run the component name request
		oltpMetrics.cryptoAlgorithmsHistogram.Record(ctx, elapsedTime) // Record algorithm request time
	}
}
