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

package responsebuilder

import (
	"context"
	"errors"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"net/http"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/httphelper"
)

// ToAlgorithmResponse converts an internal CryptoOutput structure into an AlgorithmResponse.
//
// This function marshals the internal DTO to JSON, unmarshals it to the protobuf response format,
// and enriches it with status information. It's used for endpoints that return algorithm data
// for a specific component version without grouping.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for error logging
//   - output: Internal DTO containing cryptography data for a specific version
//
// Returns:
//   - *pb.AlgorithmResponse: The formatted protobuf response with status
//   - error: Non-nil if marshalling/unmarshalling fails
func ToAlgorithmResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoOutput) (*pb.AlgorithmResponse, error) {
	if output.Cryptography == nil {
		return nil, errors.New("no cryptography found")
	}
	s.Debugf("convertCryptoOutputToComponents: %v", output)
	response := &pb.AlgorithmResponse{
		Purls:  make([]*pb.AlgorithmResponse_Purls, 0, len(output.Cryptography)),
		Status: &common.StatusResponse{},
	}
	for _, component := range output.Cryptography {
		algorithms := make([]*pb.Algorithm, 0, len(component.Algorithms))
		for _, alg := range component.Algorithms {
			algorithms = append(algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
		compAlgorithms := &pb.AlgorithmResponse_Purls{
			Purl:       component.Purl,
			Version:    component.Version,
			Algorithms: algorithms,
		}
		if component.Status.StatusCode != domain.Success {
			compAlgorithms.ErrorMessage = &component.Status.Message
			compAlgorithms.ErrorCode = statusCodeToErrorCode(component.Status.StatusCode)
		}
		response.Purls = append(response.Purls, compAlgorithms)
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

func getComponentAlgorithms(cryptoOutputItem domain.CryptoOutputItem) *pb.ComponentAlgorithms {
	algorithms := make([]*pb.Algorithm, 0, len(cryptoOutputItem.Algorithms))
	for _, alg := range cryptoOutputItem.Algorithms {
		algorithms = append(algorithms, &pb.Algorithm{
			Algorithm: alg.Algorithm,
			Strength:  alg.Strength,
		})
	}
	componentAlgorithms := &pb.ComponentAlgorithms{
		Purl:        cryptoOutputItem.Purl,
		Version:     cryptoOutputItem.Version,
		Requirement: cryptoOutputItem.Requirement,
		Algorithms:  algorithms,
	}

	if cryptoOutputItem.Status.StatusCode != domain.Success {
		componentAlgorithms.ErrorMessage = &cryptoOutputItem.Status.Message
		componentAlgorithms.ErrorCode = statusCodeToErrorCode(cryptoOutputItem.Status.StatusCode)
	}
	return componentAlgorithms
}

// ToComponentsAlgorithmsResponse converts CryptoOutput into a ComponentsAlgorithmsResponse.
//
// This function builds a response containing multiple components, each with their associated
// cryptographic algorithms for specific versions. It manually constructs the component and
// algorithm structures from the internal DTO, including purl, version, requirement, and
// algorithm details (algorithm name and strength).
//
// The function validates that cryptography data exists before processing and returns an error
// if the input contains no cryptography information.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing cryptography data for multiple components
//
// Returns:
//   - *pb.ComponentsAlgorithmsResponse: Response containing all components with their algorithms and status
//   - error: Non-nil if cryptography data is missing
func ToComponentsAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoOutput) (*pb.ComponentsAlgorithmsResponse, error) {
	if output.Cryptography == nil {
		return nil, errors.New("no cryptography found")
	}
	s.Debugf("convertCryptoOutputToComponents: %v", output)
	response := &pb.ComponentsAlgorithmsResponse{
		Components: make([]*pb.ComponentAlgorithms, 0, len(output.Cryptography)),
		Status:     &common.StatusResponse{},
	}
	for _, component := range output.Cryptography {
		response.Components = append(response.Components, getComponentAlgorithms(component))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

// ToComponentAlgorithmsResponse converts CryptoOutput into a ComponentAlgorithmsResponse.
//
// This function builds a response for a single component with its associated cryptographic
// algorithms for a specific version. It manually constructs the component and algorithm
// structures from the internal DTO, including purl, version, requirement, and algorithm
// details (algorithm name and strength).
//
// While the input may contain multiple components, this function is designed for
// single-component responses and will process all items in the loop (though typically
// only one component is expected).
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing cryptography data for a component
//
// Returns:
//   - *pb.ComponentAlgorithmsResponse: Response containing a single component with algorithms and status
//   - error: Non-nil if cryptography data is missing
func ToComponentAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoOutput) (*pb.ComponentAlgorithmsResponse, error) {
	if output.Cryptography == nil {
		return nil, errors.New("no cryptography found")
	}
	s.Debugf("convertCryptoOutputToComponents: %v", output)
	response := &pb.ComponentAlgorithmsResponse{
		Component: &pb.ComponentAlgorithms{},
		Status:    &common.StatusResponse{},
	}
	for _, component := range output.Cryptography {
		response.Component = getComponentAlgorithms(component)
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully.",
	}
	return response, nil
}
