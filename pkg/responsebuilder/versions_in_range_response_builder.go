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
	"net/http"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/httphelper"
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
func ToVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.VersionsInRangeOutput) (*pb.VersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	var response = &pb.VersionsInRangeResponse{
		Purls:  make([]*pb.VersionsInRangeResponse_Purl, 0),
		Status: &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		componentVersionsInRange := &pb.VersionsInRangeResponse_Purl{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		}
		if v.Status.StatusCode != domain.Success {
			componentVersionsInRange.ErrorMessage = &v.Status.Message
			componentVersionsInRange.ErrorCode = statusCodeToErrorCode(v.Status.StatusCode)
		}
		response.Purls = append(response.Purls, componentVersionsInRange)
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Versions in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
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
func ToComponentsVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.VersionsInRangeOutput) (*pb.ComponentsVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	var response = &pb.ComponentsVersionsInRangeResponse{
		Components: make([]*pb.ComponentsVersionsInRangeResponse_Component, 0),
		Status:     &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		componentVersionsInRange := &pb.ComponentsVersionsInRangeResponse_Component{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		}
		if v.Status.StatusCode != domain.Success {
			componentVersionsInRange.ErrorMessage = &v.Status.Message
			componentVersionsInRange.ErrorCode = statusCodeToErrorCode(v.Status.StatusCode)
		}
		response.Components = append(response.Components, componentVersionsInRange)
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Versions in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
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
func ToComponentVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.VersionsInRangeOutput) (*pb.ComponentVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	if (output.Versions == nil) || (len(output.Versions) == 0) {
		return nil, errors.New("no versions found")
	}
	var response = &pb.ComponentVersionsInRangeResponse{
		Component: &pb.ComponentVersionsInRangeResponse_Component{},
		Status:    &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		componentVersionsInRange := &pb.ComponentVersionsInRangeResponse_Component{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		}
		if v.Status.StatusCode != domain.Success {
			componentVersionsInRange.ErrorMessage = &v.Status.Message
			componentVersionsInRange.ErrorCode = statusCodeToErrorCode(v.Status.StatusCode)
		}

		response.Component = componentVersionsInRange
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Versions in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}
