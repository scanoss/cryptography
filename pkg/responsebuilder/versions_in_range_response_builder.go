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

// ToVersionsInRangeResponse converts a VersionsInRangeOutput structure into a VersionsInRangeResponse.
//
// This function marshals the internal DTO to JSON, unmarshals it to the protobuf response format,
// and enriches it with status information. It's used for endpoints that return version availability
// information (versions with and without cryptographic detections) for components within a range
// without grouping by component.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for error and debug logging
//   - output: Internal DTO containing version availability data
//
// Returns:
//   - *pb.VersionsInRangeResponse: The formatted protobuf response with status
//   - error: Non-nil if marshalling/unmarshalling fails
func ToVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.VersionsInRangeResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem marshalling Versions output")
	}
	var response pb.VersionsInRangeResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem unmarshalling Versions output")
	}
	response = *httpresponsehelper.NewVersionsInRangeResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil
}

// ToComponentsVersionsInRangeResponse converts VersionsInRangeOutput to ComponentsVersionsInRangeResponse.
//
// This function builds a response containing multiple components, each with their version
// availability information within the specified range. It manually constructs the component
// structures from the internal DTO, including purl, versions with cryptographic detections
// (VersionsWith), and versions without detections (VersionsWithout).
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing version availability data for multiple components
//
// Returns:
//   - *pb.ComponentsVersionsInRangeResponse: Response containing all components with version data and status
//   - error: Always returns nil error in current implementation
func ToComponentsVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.ComponentsVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	var response = &pb.ComponentsVersionsInRangeResponse{
		Components: make([]*pb.ComponentsVersionsInRangeResponse_Component, 0),
		Status:     &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		response.Components = append(response.Components, &pb.ComponentsVersionsInRangeResponse_Component{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		})
	}
	response = httpresponsehelper.NewVersionsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

// ToComponentVersionsInRangeResponse converts VersionsInRangeOutput to ComponentVersionsInRangeResponse.
//
// This function builds a response for a single component with its version availability
// information within the specified range. It manually constructs the component structure
// from the internal DTO, including purl, versions with cryptographic detections
// (VersionsWith), and versions without detections (VersionsWithout).
//
// While the input may contain multiple components, this function is designed for
// single-component responses and will process all items in the loop (though typically
// only one component is expected).
//
// The function validates that version data exists before processing.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing version availability data for a component
//
// Returns:
//   - *pb.ComponentVersionsInRangeResponse: Response containing a single component with version data and status
//   - error: Non-nil if version data is missing or empty
func ToComponentVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.ComponentVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	if (output.Versions == nil) || (len(output.Versions) == 0) {
		return nil, errors.New("no versions found")
	}
	var response = &pb.ComponentVersionsInRangeResponse{
		Component: &pb.ComponentVersionsInRangeResponse_Component{},
		Status:    &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		response.Component = &pb.ComponentVersionsInRangeResponse_Component{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		}
	}
	response = httpresponsehelper.NewVersionsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
