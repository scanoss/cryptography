// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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

// Package service implements the gRPC service endpoints
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	gd "github.com/scanoss/go-grpc-helper/pkg/grpc/database"

	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/usecase"
)

type cryptographyServer struct {
	pb.CryptographyServer
	db     *sqlx.DB
	config *myconfig.ServerConfig
}

// NewCryptographyServer creates a new instance of Cryptography Server.
func NewCryptographyServer(db *sqlx.DB, config *myconfig.ServerConfig) pb.CryptographyServer {
	setupMetrics()
	return &cryptographyServer{db: db, config: config}
}

// Echo sends back the same message received.
func (c cryptographyServer) Echo(ctx context.Context, request *common.EchoRequest) (*common.EchoResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Infof("Received (%v): %v", ctx, request.GetMessage())
	return &common.EchoResponse{Message: request.GetMessage()}, nil
}

func (c cryptographyServer) GetAlgorithms(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := convertCryptoInput(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCrypto(ctx, s, conn, c.config)
	dtoCrypto, notFound, err := cryptoUc.GetCrypto(dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	cryptoResponse, err := convertCryptoOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: "Success"}
	if notFound > 0 {
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		statusResp.Message = fmt.Sprintf("No information found for %d purl(s)", notFound)
	}
	return &pb.AlgorithmResponse{Purls: cryptoResponse.Purls, Status: &statusResp}, nil
}

func (c cryptographyServer) GetAlgorithmsInRange(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := convertCryptoInput(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCryptoMajor(ctx, s, conn, c.config)
	dtoCrypto, notFound, err := cryptoUc.GetCryptoInRange(dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	cryptoResponse, err := convertCryptoMajorOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: "Success"}
	if notFound > 0 {
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		statusResp.Message = fmt.Sprintf("No information found for %d purl(s)", notFound)
	}
	return &pb.AlgorithmsInRangeResponse{Purls: cryptoResponse.Purls, Status: &statusResp}, nil
}

// telemetryRequestTime records the crypto algorithms request time to telemetry.
func telemetryRequestTime(ctx context.Context, config *myconfig.ServerConfig, requestStartTime time.Time) {
	if config.Telemetry.Enabled {
		elapsedTime := time.Since(requestStartTime).Milliseconds()     // Time taken to run the component name request
		oltpMetrics.cryptoAlgorithmsHistogram.Record(ctx, elapsedTime) // Record algorithm request time
	}
}
