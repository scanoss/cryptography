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
	"encoding/json"
	"errors"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/httpresponsehelper"
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
func ToAlgorithmResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.AlgorithmResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.AlgorithmResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	response = *httpresponsehelper.NewAlgorithmResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil

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
func ToComponentsAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentsAlgorithmsResponse, error) {
	if output.Cryptography == nil {
		return nil, errors.New("no cryptography found")
	}
	s.Debugf("convertCryptoOutputToComponents: %v", output)
	response := &pb.ComponentsAlgorithmsResponse{
		Components: make([]*pb.ComponentAlgorithms, 0, len(output.Cryptography)),
		Status:     &common.StatusResponse{},
	}
	for _, component := range output.Cryptography {
		algorithms := make([]*pb.Algorithm, 0, len(component.Algorithms))
		for _, alg := range component.Algorithms {
			algorithms = append(algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
		response.Components = append(response.Components, &pb.ComponentAlgorithms{
			Purl:        component.Purl,
			Version:     component.Version,
			Requirement: component.Requirement,
			Algorithms:  algorithms,
		})
	}
	response = httpresponsehelper.NewAlgorithmResponseHelper(response).WithStatus(ctx, s, output)
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
func ToComponentAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentAlgorithmsResponse, error) {
	if output.Cryptography == nil {
		return nil, errors.New("no cryptography found")
	}
	s.Debugf("convertCryptoOutputToComponents: %v", output)
	response := &pb.ComponentAlgorithmsResponse{
		Component: &pb.ComponentAlgorithms{},
		Status:    &common.StatusResponse{},
	}

	for _, component := range output.Cryptography {
		algorithms := make([]*pb.Algorithm, 0, len(component.Algorithms))
		for _, alg := range component.Algorithms {
			algorithms = append(algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
		response.Component = &pb.ComponentAlgorithms{
			Purl:        component.Purl,
			Version:     component.Version,
			Requirement: component.Requirement,
			Algorithms:  algorithms,
		}
	}
	response = httpresponsehelper.NewAlgorithmResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
