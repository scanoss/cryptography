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
	"net/http"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/httphelper"
)

// ToAlgorithmsInRangeResponse converts an internal CryptoInRangeOutput structure into an AlgorithmsInRangeResponse.
//
// This function marshals the internal DTO to JSON, unmarshals it to the protobuf response format,
// and enriches it with status information. It's used for endpoints that return algorithm data
// for components within a version range without grouping by component.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for error and debug logging
//   - output: Internal DTO containing cryptography data for a version range
//
// Returns:
//   - *pb.AlgorithmsInRangeResponse: The formatted protobuf response with status
//   - error: Non-nil if marshalling/unmarshalling fails
func ToAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoInRangeOutput) (*pb.AlgorithmsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.AlgorithmsInRangeResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return &response, nil
}

func getAlgorithmsInRange(output domain.CryptoInRangeOutputItem) *pb.ComponentsAlgorithmsInRangeResponse_Component {
	var algorithms = make([]*pb.Algorithm, 0, len(output.Algorithms))
	for _, alg := range output.Algorithms {
		algorithms = append(algorithms, &pb.Algorithm{
			Algorithm: alg.Algorithm,
			Strength:  alg.Strength,
		})
	}
	algorithmsInRange := &pb.ComponentsAlgorithmsInRangeResponse_Component{
		Purl:       output.Purl,
		Versions:   output.Versions,
		Algorithms: algorithms,
	}
	if output.Status.StatusCode != domain.Success {
		algorithmsInRange.ErrorMessage = &output.Status.Message
		algorithmsInRange.ErrorCode = statusCodeToErrorCode(output.Status.StatusCode)
	}
	return algorithmsInRange
}

// ToComponentsAlgorithmsInRangeResponse converts CryptoInRangeOutput to ComponentsAlgorithmsInRangeResponse.
//
// This function builds a response containing multiple components, each with their associated
// cryptographic algorithms found within the specified version range. It manually constructs
// the component and algorithm structures from the internal DTO rather than using JSON marshalling.
//
// The function validates that cryptography data exists before processing and returns an error
// if the input contains no cryptography information.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing cryptography data for multiple components in a version range
//
// Returns:
//   - *pb.ComponentsAlgorithmsInRangeResponse: Response containing all components with their algorithms and status
//   - error: Non-nil if cryptography data is missing or empty
func ToComponentsAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoInRangeOutput) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
	s.Debugf("convertComponentsCryptoInRangeOutput: %v", output)
	if (output.Cryptography == nil) || (len(output.Cryptography) == 0) {
		return nil, errors.New("no cryptography found")
	}
	var response = &pb.ComponentsAlgorithmsInRangeResponse{
		Components: make([]*pb.ComponentsAlgorithmsInRangeResponse_Component, 0),
		Status:     &common.StatusResponse{},
	}
	for _, c := range output.Cryptography {
		response.Components = append(response.Components, getAlgorithmsInRange(c))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

// ToComponentAlgorithmsInRangeResponse converts CryptoInRangeOutput to ComponentAlgorithmsInRangeResponse.
//
// This function builds a response for a single component with its associated cryptographic
// algorithms found within the specified version range. While the input may contain multiple
// components, this function is designed for single-component responses and will process
// all items in the loop (though typically only one component is expected).
//
// The function validates that cryptography data exists before processing and manually
// constructs the component and algorithm structures from the internal DTO.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing cryptography data for a component in a version range
//
// Returns:
//   - *pb.ComponentAlgorithmsInRangeResponse: Response containing a single component with algorithms and status
//   - error: Non-nil if cryptography data is missing or empty
func ToComponentAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.CryptoInRangeOutput) (*pb.ComponentAlgorithmsInRangeResponse, error) {
	s.Debugf("convertComponentsCryptoInRangeOutput: %v", output)
	if (output.Cryptography == nil) || (len(output.Cryptography) == 0) {
		return nil, errors.New("no cryptography found")
	}
	var response = &pb.ComponentAlgorithmsInRangeResponse{
		Component: &pb.ComponentAlgorithmsInRangeResponse_Component{},
		Status:    &common.StatusResponse{},
	}
	for _, c := range output.Cryptography {
		algorithmsInRange := getAlgorithmsInRange(c)

		algorithmInRangeComponent := &pb.ComponentAlgorithmsInRangeResponse_Component{
			Versions:   algorithmsInRange.Versions,
			Purl:       algorithmsInRange.Purl,
			Algorithms: algorithmsInRange.Algorithms,
		}
		if c.Status.StatusCode != domain.Success {
			algorithmInRangeComponent.ErrorCode = algorithmsInRange.ErrorCode
			algorithmInRangeComponent.ErrorMessage = algorithmsInRange.ErrorMessage
		}
		response.Component = algorithmInRangeComponent
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}
