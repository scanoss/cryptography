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

// Package grpc handles all the gRPC communication for the Cryptography Service
// It takes care of starting and stopping the listener, etc.
package grpc

import (
	"github.com/scanoss/go-grpc-helper/pkg/grpc/otel"
	gs "github.com/scanoss/go-grpc-helper/pkg/grpc/server"
	myconfig "scanoss.com/cryptography/pkg/config"

	pb "github.com/scanoss/papi/api/cryptographyv2"
	"google.golang.org/grpc"
)

// RunServer runs gRPC service to publish.
func RunServer(config *myconfig.ServerConfig, v2API pb.CryptographyServer, port string,
	allowedIPs, deniedIPs []string, startTLS bool, version string) (*grpc.Server, error) {
	// Start up Open Telemetry is requested
	var oltpShutdown = func() {}
	if config.Telemetry.Enabled {
		var err error
		oltpShutdown, err = otel.InitTelemetryProviders(config.App.Name, "scanoss-cryptography", version,
			config.Telemetry.OltpExporter, otel.GetTraceSampler(config.App.Mode), false)
		if err != nil {
			return nil, err
		}
	}
	// Configure the port, interceptors, TLS and register the service
	listen, server, err := gs.SetupGrpcServer(port, config.TLS.CertFile, config.TLS.KeyFile,
		allowedIPs, deniedIPs, startTLS, config.Filtering.BlockByDefault, config.Filtering.TrustProxy,
		config.Telemetry.Enabled)
	if err != nil {
		oltpShutdown()
		return nil, err
	}
	// Register the service API and start the server in the background
	pb.RegisterCryptographyServer(server, v2API)
	go func() {
		gs.StartGrpcServer(listen, server, startTLS)
		oltpShutdown()
	}()
	return server, nil
}
