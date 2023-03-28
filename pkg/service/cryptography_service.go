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

	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	zlog "scanoss.com/cryptography/pkg/logger"
	"scanoss.com/cryptography/pkg/usecase"
)

type cryptographyServer struct {
	pb.CryptographyServer
	db     *sqlx.DB
	config *myconfig.ServerConfig
}

// NewCryptographyServer creates a new instance of Cryptography Server
func NewCryptographyServer(db *sqlx.DB, config *myconfig.ServerConfig) pb.CryptographyServer {
	return &cryptographyServer{db: db, config: config}
}

// Echo sends back the same message received
func (c cryptographyServer) Echo(ctx context.Context, request *common.EchoRequest) (*common.EchoResponse, error) {
	zlog.S.Infof("Received (%v): %v", ctx, request.GetMessage())
	return &common.EchoResponse{Message: request.GetMessage()}, nil
}

func (c cryptographyServer) GetAlgorithms(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmResponse, error) {

	zlog.S.Infof("Processing Cryptography request: %v", request)
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if reqPurls == nil || len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := convertCryptoInput(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		zlog.S.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer closeDbConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCrypto(ctx, conn)
	dtoCrypto, err := cryptoUc.GetCrypto(dtoRequest)

	if err != nil {
		zlog.S.Errorf("Failed to get dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	zlog.S.Debugf("Parsed Crypto: %+v", dtoCrypto)
	cryptoResponse, err := convertCryptoOutput(dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		zlog.S.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: "Success"}
	return &pb.AlgorithmResponse{Purls: cryptoResponse.Purls, Status: &statusResp}, nil
}

// closeDbConnection closes the specified database connection
func closeDbConnection(conn *sqlx.Conn) {
	zlog.S.Debugf("Closing DB Connection: %v", conn)
	err := conn.Close()
	if err != nil {
		zlog.S.Warnf("Warning: Problem closing database connection: %v", err)
	}
}
