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
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"net/http"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/httphelper"
)

// ToHintsResponse converts an internal HintsOutput structure into a HintsResponse.
//
// This function marshals the internal DTO to JSON, unmarshals it to the protobuf response format,
// and enriches it with status information. It's used for endpoints that return encryption hint
// detections for specific component versions without grouping by component.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for error and debug logging
//   - output: Internal DTO containing encryption hints data
//
// Returns:
//   - *pb.HintsResponse: The formatted protobuf response with status
//   - error: Non-nil if marshalling/unmarshalling fails
func ToHintsResponse(ctx context.Context, s *zap.SugaredLogger, output domain.HintsOutput) (*pb.HintsResponse, error) {
	var response = &pb.HintsResponse{
		Purls:  make([]*pb.HintsResponse_Purls, 0, len(output.Hints)),
		Status: &common.StatusResponse{},
	}
	for _, hint := range output.Hints {
		hints := make([]*pb.Hint, 0, len(hint.Detections))
		for _, detection := range hint.Detections {
			hints = append(hints, &pb.Hint{
				Id:          detection.ID,
				Name:        detection.Name,
				Purl:        detection.Purl,
				Description: detection.Description,
				Category:    detection.Category,
				Url:         detection.URL,
			})
		}
		componentHints := &pb.HintsResponse_Purls{
			Purl:    hint.Purl,
			Version: hint.Version,
			Hints:   hints,
		}
		if hint.Status.StatusCode != status.Success {
			code := hint.Status.StatusCode.String()
			msg := hint.Status.Message
			componentHints.InfoMessage = &msg
			componentHints.InfoCode = &code
		}
		response.Purls = append(response.Purls, componentHints)
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Encryption's hints retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

func getComponentHints(output domain.HintsOutputItem) *pb.ComponentHints {
	hints := make([]*pb.Hint, 0, len(output.Detections))
	for _, detection := range output.Detections {
		hints = append(hints, &pb.Hint{
			Id:          detection.ID,
			Name:        detection.Name,
			Purl:        detection.Purl,
			Description: detection.Description,
			Category:    detection.Category,
			Url:         detection.URL,
		})
	}
	componentHints := &pb.ComponentHints{
		Purl:        output.Purl,
		Version:     output.Version,
		Requirement: output.Requirement,
		Hints:       hints,
	}
	if output.Status.StatusCode != status.Success {
		code := output.Status.StatusCode.String()
		msg := output.Status.Message
		componentHints.InfoMessage = &msg
		componentHints.InfoCode = &code
	}
	return componentHints
}

// ToComponentsEncryptionHintsResponse converts HintsOutput to ComponentsEncryptionHintsResponse.
//
// This function builds a response containing multiple components, each with their associated
// encryption hint detections. It manually constructs the component and hint structures from
// the internal DTO, including purl, version, requirement, and hint detection details
// (ID, name, description, category, URL).
//
// The function validates that hints data exists before processing and returns an error
// if the input contains no hints information.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for the operation
//   - output: Internal DTO containing encryption hints for multiple components
//
// Returns:
//   - *pb.ComponentsEncryptionHintsResponse: Response containing all components with their hints and status
//   - error: Non-nil if hints data is missing
func ToComponentsEncryptionHintsResponse(ctx context.Context, s *zap.SugaredLogger, output domain.HintsOutput) (*pb.ComponentsEncryptionHintsResponse, error) {
	var response = &pb.ComponentsEncryptionHintsResponse{
		Components: make([]*pb.ComponentHints, 0, len(output.Hints)),
		Status:     &common.StatusResponse{},
	}
	for _, hint := range output.Hints {
		response.Components = append(response.Components, getComponentHints(hint))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Encryption's hints retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

// ToComponentEncryptionHintsResponse converts HintsOutput to ComponentEncryptionHintsResponse.
//
// This function builds a response for a single component with its associated encryption
// hint detections. It manually constructs the component and hint structures from the
// internal DTO, including purl, version, requirement, and hint detection details
// (ID, name, description, category, URL).
//
// While the input may contain multiple components, this function is designed for
// single-component responses and will process all items in the loop (though typically
// only one component is expected).
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for the operation
//   - output: Internal DTO containing encryption hints for a component
//
// Returns:
//   - *pb.ComponentEncryptionHintsResponse: Response containing a single component with hints and status
//   - error: Non-nil if hints data is missing
func ToComponentEncryptionHintsResponse(ctx context.Context, s *zap.SugaredLogger, output domain.HintsOutput) (*pb.ComponentEncryptionHintsResponse, error) {
	var response = &pb.ComponentEncryptionHintsResponse{
		Component: &pb.ComponentHints{},
		Status:    &common.StatusResponse{},
	}
	for _, hint := range output.Hints {
		response.Component = getComponentHints(hint)
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Encryption's hints retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}
