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

// Package service implements the gRPC service endpoints
package service

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"strings"
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

const (
	ResponseMessageSUCCESS = "Success"
)

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
	dtoRequest, err := convertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
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
	dtoCrypto, summary, err := cryptoUc.GetComponentsAlgorithms(dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	if dtoCrypto.Cryptography != nil {
		cryptoResponse, err := convertCryptoOutput(s, dtoCrypto) // Convert the internal data into a response object
		if err != nil {
			s.Errorf("Failed to covnert parsed dependencies: %v", err)
			statusResp = common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		}
		return &pb.AlgorithmResponse{Purls: cryptoResponse.Purls, Status: &statusResp}, nil
	}

	return &pb.AlgorithmResponse{Status: &statusResp}, nil
}

// GetComponentsAlgorithms retrieves cryptographic algorithms for multiple components
func (c cryptographyServer) GetComponentsAlgorithms(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	if len(request.Components) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}

	dtos, err := convertComponentsRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}

	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCrypto(ctx, s, conn, c.config)
	results, summary, err := cryptoUc.GetComponentsAlgorithms(dtos)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}

	response, err := convertCryptoOutputToComponents(s, results) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Problems encountered extracting Cryptography datat : %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}

	response.Status = &statusResp
	return response, nil
}

// GetComponentAlgorithms retrieves cryptographic algorithms for a single component
func (c cryptographyServer) GetComponentAlgorithms(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")

	componentDTO, err := convertComponentRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, errors.New(err.Error())
	}

	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCrypto(ctx, s, conn, c.config)
	results, summary, err := cryptoUc.GetComponentsAlgorithms([]dtos.ComponentDTO{componentDTO})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
	}

	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}

	if results.Cryptography != nil {
		response, err := convertCryptoOutputToComponent(s, results) // Convert the internal data into a response object
		if err != nil {
			s.Errorf("Problems encountered extracting Cryptography datat : %v", err)
			statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
			return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
		}
		response.Status = &statusResp
		return response, nil
	}
	err = grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", "404"))
	if err != nil {
		s.Debugf("error setting x-http-code to trailer: %v\n", err)
	}
	return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
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
	dtoRequest, err := convertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
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
	dtoCrypto, summary, err := cryptoUc.GetCryptoInRange(dtoRequest)
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
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}

	return &pb.AlgorithmsInRangeResponse{Purls: cryptoResponse.Purls, Status: &statusResp}, nil
}

func (c cryptographyServer) GetComponentsAlgorithmsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	if len(request.Components) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := convertComponentsRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCryptoMajor(ctx, s, conn, c.config)
	dtoCrypto, summary, err := cryptoUc.GetCryptoInRange(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	response, err := convertComponentsCryptoInRangeOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

func (c cryptographyServer) GetComponentAlgorithmsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	componentDTOS, err := convertComponentRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewCryptoMajor(ctx, s, conn, c.config)
	dtoCrypto, summary, err := cryptoUc.GetCryptoInRange([]dtos.ComponentDTO{componentDTOS})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	response, err := convertComponentCryptoInRangeOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

func (c cryptographyServer) GetVersionsInRange(ctx context.Context, request *common.PurlRequest) (*pb.VersionsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := convertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewVersionsUsingCrypto(ctx, s, conn, c.config)
	dtoCrypto, summary, err := cryptoUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, nil
	}
	versionsResponse, err := convertVersionsInRangeUsingCryptoOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}

	return &pb.VersionsInRangeResponse{Purls: versionsResponse.Purls, Status: &statusResp}, nil
}

// GetComponentsVersionsInRange retrieves version information for multiple components within specified version ranges
// showing which versions use cryptographic algorithms and which do not
func (c cryptographyServer) GetComponentsVersionsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsVersionsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	if len(request.Components) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := convertComponentsRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewVersionsUsingCrypto(ctx, s, conn, c.config)
	dtoCrypto, summary, err := cryptoUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, nil
	}
	response, err := convertToComponentsVersionInRangeOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to covnert parsed dependencies: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

// GetComponentVersionsInRange retrieves version information for a single component within a specified version range
// showing which versions use cryptographic algorithms and which do not
func (c cryptographyServer) GetComponentVersionsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentVersionsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	componentDTOS, err := convertComponentRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	cryptoUc := usecase.NewVersionsUsingCrypto(ctx, s, conn, c.config)
	dtoCrypto, summary, err := cryptoUc.GetVersionsInRangeUsingCrypto([]dtos.ComponentDTO{componentDTOS})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, nil
	}
	response, err := convertToComponentVersionInRangeOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert cryptography data to response: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

func (c cryptographyServer) GetHintsInRange(ctx context.Context, request *common.PurlRequest) (*pb.HintsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := convertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	dtoEC, summary, err := ecDetectionUC.GetDetectionsInRange(dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem encountered extracting Cryptography data")
	}
	ecResponse, err := convertECOutput(s, dtoEC) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert cryptographic response: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing cryptography data")
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}

	return &pb.HintsInRangeResponse{Purls: ecResponse.Purls, Status: &statusResp}, nil
}

func (c cryptographyServer) GetComponentsHintsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsHintsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	if len(request.Components) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := convertComponentsRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	dtoEC, summary, err := ecDetectionUC.GetDetectionsInRange(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get hints in range: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problem getting hints in range")
	}
	response, err := convertToComponentsHintsInRangeOutput(s, dtoEC) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed convert hints to response output: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problems getting hints in range")
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

func (c cryptographyServer) GetComponentHintsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentHintsInRangeResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	componentDTOS, err := convertComponentRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	dtoEC, summary, err := ecDetectionUC.GetDetectionsInRange([]dtos.ComponentDTO{componentDTOS})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("failed to get hints in range")
	}
	response, err := convertToComponentHintsInRangeOutput(s, dtoEC) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Problems coverting cryptography data to response output: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("problems encountered extracting hints in range data")
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := common.StatusResponse{Status: common.StatusCode_SUCCESS, Message: ResponseMessageSUCCESS}
	var messages []string
	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
	}
	if len(messages) == 0 {
		statusResp.Message = ResponseMessageSUCCESS
	} else {
		statusResp.Message = strings.Join(messages, "/")
	}
	response.Status = &statusResp
	return response, nil
}

func (c cryptographyServer) GetEncryptionHints(ctx context.Context, request *common.PurlRequest) (*pb.HintsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing Crypto hints algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := convertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	dtoEC, summary, err := ecDetectionUC.GetDetections(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}

	ecResponse, err := convertHintsOutput(s, dtoEC) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert to hints output: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := buildStatusResponse(ctx, s, summary)
	return &pb.HintsResponse{Purls: ecResponse.Purls, Status: statusResp}, nil
}

func (c cryptographyServer) GetComponentsEncryptionHints(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsEncryptionHintsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing Crypto hints algorithms request...")
	//handle request
	componentDTOS, resp, err := handleComponentsRequest(request,
		func(status *common.StatusResponse) *pb.ComponentsEncryptionHintsResponse {
			return &pb.ComponentsEncryptionHintsResponse{Status: status}
		})
	if err != nil {
		setHttpCodeOnTrailer(ctx, s)
		return resp, nil
	}

	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentsEncryptionHintsResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	encryptionHints, summary, err := ecDetectionUC.GetDetections(componentDTOS)
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}

	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := buildStatusResponse(ctx, s, summary)

	if encryptionHints.Hints == nil {
		return &pb.ComponentsEncryptionHintsResponse{Status: statusResp}, nil
	}
	response, err := convertEncryptionHintsToComponentsEncryptionOutput(encryptionHints) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert to hints output: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	response.Status = statusResp
	return response, nil
}

func (c cryptographyServer) GetComponentEncryptionHints(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentEncryptionHintsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing Crypto hints algorithms request...")
	// Make sure we have Cryptography data to query
	componentDTOS, err := convertComponentRequestToComponentDTO(request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New(err.Error())
	}
	conn, err := c.db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		s.Errorf("Failed to get a database connection from the pool: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Failed to get database pool connection"}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New("problem getting database pool connection")
	}
	defer gd.CloseSQLConnection(conn)
	// Search the KB for information about each Cryptography
	ecDetectionUC := usecase.NewECDetection(ctx, s, conn, c.config)
	encryptionHints, summary, err := ecDetectionUC.GetDetections([]dtos.ComponentDTO{componentDTOS})
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}

	telemetryRequestTime(ctx, c.config, requestStartTime)
	// Set the status and respond with the data
	statusResp := buildStatusResponse(ctx, s, summary)

	// Check for nil hints first
	if encryptionHints.Hints == nil {
		return &pb.ComponentEncryptionHintsResponse{Status: statusResp}, nil
	}

	response, err := convertEncryptionHintsToComponentEncryptionOutput(encryptionHints) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert to hints output: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	response.Status = statusResp
	return response, nil
}

func handleComponentsRequest[T any](request *common.ComponentsRequest, createResponse func(*common.StatusResponse) T) ([]dtos.ComponentDTO, T, error) {
	var zero T
	componentDTOS, err := convertComponentsRequestToComponentDTO(request)
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return []dtos.ComponentDTO{}, createResponse(&statusResp), errors.New(err.Error())
	}

	return componentDTOS, zero, nil
}

// buildStatusResponse constructs a StatusResponse based on PURL processing results and sets appropriate HTTP status codes.
func buildStatusResponse(ctx context.Context, s *zap.SugaredLogger, summary models.QuerySummary) *common.StatusResponse {
	var messages []string

	if len(summary.PurlsFailedToParse) > 0 {
		messages = append(messages, fmt.Sprintf("Failed to parse %d purl(s):%s", len(summary.PurlsFailedToParse), strings.Join(summary.PurlsFailedToParse, ",")))
	}

	if len(summary.PurlsNotFound) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find %d purl(s):%s", len(summary.PurlsNotFound), strings.Join(summary.PurlsNotFound, ",")))
	}

	if len(summary.PurlsWOInfo) > 0 {
		messages = append(messages, fmt.Sprintf("Can't find information for %d purl(s):%s", len(summary.PurlsWOInfo), strings.Join(summary.PurlsWOInfo, ",")))
	}

	statusResp := common.StatusResponse{
		Status: common.StatusCode_SUCCESS,
	}

	httpStatusCode := "200"

	statusResp.Message = ResponseMessageSUCCESS
	if len(messages) > 0 {
		statusResp.Message = strings.Join(messages, " | ")
	}

	// Calculate totals
	totalFailedToParse := len(summary.PurlsFailedToParse)
	totalNotFound := len(summary.PurlsNotFound)
	totalWOInfo := len(summary.PurlsWOInfo)
	totalFailed := totalFailedToParse + totalNotFound + totalWOInfo
	totalSuccessful := summary.TotalPurls - totalFailed

	s.Debugf("PURL Summary - Total: %d, Successful: %d, Failed to parse: %d, Not found: %d, No info: %d",
		summary.TotalPurls, totalSuccessful, totalFailedToParse, totalNotFound, totalWOInfo)

	// Status determination logic:
	// 1. Check for partial failures with more missing info than parse errors
	// 2. Check for complete parse failure (all PURLs malformed)
	// 3. Check for partial parse failures
	// 4. Check for complete info-missing failure (all PURLs lack data)
	// 5. Default to success (all PURLs processed successfully)
	switch {
	case totalWOInfo > 0 && totalWOInfo >= totalFailedToParse && totalWOInfo < summary.TotalPurls:
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		break

	case totalFailedToParse >= summary.TotalPurls:
		statusResp.Status = common.StatusCode_FAILED
		httpStatusCode = "400"
		break

	case totalFailedToParse > 0 && totalFailedToParse < summary.TotalPurls:
		statusResp.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		break

	case totalWOInfo >= summary.TotalPurls:
		httpStatusCode = "404"
		statusResp.Status = common.StatusCode_FAILED
		break

	default:
		// All PURLs succeeded
		statusResp.Status = common.StatusCode_SUCCESS
	}
	err := grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", httpStatusCode))
	if err != nil {
		s.Debugf("error setting x-http-code to trailer: %v\n", err)
	}
	return &statusResp
}

func setHttpCodeOnTrailer(ctx context.Context, s *zap.SugaredLogger) {
	err := grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", "400"))
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
