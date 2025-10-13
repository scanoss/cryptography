// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package handlers

import (
	"context"
	myconfig "scanoss.com/cryptography/pkg/config"
	"time"
)

// telemetryRequestTime records cryptographic algorithm request duration to OpenTelemetry.
//
// This function calculates the elapsed time since the request started and records it
// to the OpenTelemetry histogram for performance monitoring. Recording only occurs
// if telemetry is enabled in the server configuration.
//
// Parameters:
//   - ctx: Context for the telemetry recording
//   - config: Server configuration containing telemetry settings
//   - requestStartTime: Time when the request processing began
func telemetryRequestTime(ctx context.Context, config *myconfig.ServerConfig, requestStartTime time.Time) {
	if config.Telemetry.Enabled {
		elapsedTime := time.Since(requestStartTime).Milliseconds()     // Time taken to run the component name request
		oltpMetrics.cryptoAlgorithmsHistogram.Record(ctx, elapsedTime) // Record algorithm request time
	}
}
