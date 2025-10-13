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
	"errors"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/responsebuilder"
	"scanoss.com/cryptography/pkg/usecase"
)

// CryptographyAlgorithmHandler handles gRPC requests for cryptographic algorithm information.
//
// This handler processes requests to retrieve cryptographic algorithms used by components
// at specific versions. It coordinates with the cryptography use case layer to query
// the knowledge base and build appropriate responses.
type CryptographyAlgorithmHandler struct {
	cryptoUseCase usecase.CryptoUseCase
	config        *myconfig.ServerConfig
}

// NewCryptographyAlgorithmHandler creates a new CryptographyAlgorithmHandler instance.
//
// This constructor initializes the handler with a cryptography use case that provides
// access to the knowledge base for querying algorithm information.
//
// Parameters:
//   - db: Database connection for use case operations
//   - config: Server configuration including telemetry settings
//
// Returns:
//   - *CryptographyAlgorithmHandler: Initialized handler ready to process requests
func NewCryptographyAlgorithmHandler(db *sqlx.DB, config *myconfig.ServerConfig) *CryptographyAlgorithmHandler {
	// setupMetrics()
	return &CryptographyAlgorithmHandler{
		config:        config,
		cryptoUseCase: *usecase.NewCrypto(db, config),
	}
}

// GetAlgorithms retrieves cryptographic algorithms for components using legacy request format.
//
// This method supports the deprecated PurlRequest format for backward compatibility.
// It converts the legacy request to internal DTO format, queries the knowledge base,
// and builds an AlgorithmResponse.
//
// Deprecated: Use GetComponentsAlgorithms instead. This method will be removed when
// the legacy PurlRequest format is fully deprecated.
//
// Parameters:
//   - ctx: Request context containing logger and trace information
//   - request: Legacy PurlRequest containing component purls
//
// Returns:
//   - *pb.AlgorithmResponse: Response with algorithm data and status
//   - error: Non-nil if request validation fails (response status also set to FAILED)
func (c CryptographyAlgorithmHandler) GetAlgorithms(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}

	output, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, dtoRequest)
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'AlgorithmResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}
	response, err := responsebuilder.ToAlgorithmResponse(ctx, s, output)
	if err != nil {
		statusResp := &common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: statusResp}, nil //nolint:nilerr
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

// GetComponentsAlgorithms retrieves cryptographic algorithms for multiple components.
//
// This method processes a ComponentsRequest containing multiple component specifications
// (purl and version/requirement). It validates the request, queries the knowledge base
// for algorithm information, and returns a structured response with all components and
// their associated algorithms.
//
// The response includes algorithm names and strength ratings for each component at the
// specified version or requirement. StatusCode codes indicate success or failure with
// descriptive messages.
//
// Parameters:
//   - ctx: Request context containing logger and trace information
//   - request: ComponentsRequest with multiple component specifications
//
// Returns:
//   - *pb.ComponentsAlgorithmsResponse: Response with algorithms for all components and status
//   - error: Always nil (errors are communicated via response status)
func (c CryptographyAlgorithmHandler) GetComponentsAlgorithms(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	componentDTOS, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsAlgorithmsResponse {
			return &pb.ComponentsAlgorithmsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil // TODO: Implement status Errors gRPC status.Errorf(codes.InvalidArgument, "Bad request")
	}
	output, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}
	response, err := responsebuilder.ToComponentsAlgorithmsResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'ComponentsAlgorithmsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

// GetComponentAlgorithms retrieves cryptographic algorithms for a single component.
//
// This method processes a ComponentRequest for a single component specification
// (purl and version/requirement). It validates the request, queries the knowledge base,
// and returns the algorithms associated with that component.
//
// The response includes algorithm names and strength ratings. StatusCode codes indicate
// success or failure with descriptive messages.
//
// Parameters:
//   - ctx: Request context containing logger and trace information
//   - request: ComponentRequest with single component specification
//
// Returns:
//   - *pb.ComponentAlgorithmsResponse: Response with algorithms for the component and status
//   - error: Always nil (errors are communicated via response status)
func (c CryptographyAlgorithmHandler) GetComponentAlgorithms(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsResponse, error) {
	requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentAlgorithmsResponse {
			return &pb.ComponentAlgorithmsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	output, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
	}
	response, err := responsebuilder.ToComponentAlgorithmsResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'ComponentsAlgorithmsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
	}
	telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}
