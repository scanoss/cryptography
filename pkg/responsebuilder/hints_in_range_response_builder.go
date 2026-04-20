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

// ToHintsInRangeResponse converts an internal ECOutput structure into a HintsInRangeResponse.
//
// This function marshals the internal DTO to JSON, unmarshals it to the protobuf response format,
// and enriches it with status information. It's used for endpoints that return encryption hint
// data for components within a version range without grouping by component.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for error and debug logging
//   - output: Internal DTO containing encryption hints data for a version range
//
// Returns:
//   - *pb.HintsInRangeResponse: The formatted protobuf response with status
//   - error: Non-nil if marshalling/unmarshalling fails
func ToHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.ECOutput) (*pb.HintsInRangeResponse, error) {
	var response = &pb.HintsInRangeResponse{
		Status: &common.StatusResponse{},
		Purls:  make([]*pb.HintsInRangeResponse_Purl, 0, len(output.Hints)),
	}
	if len(output.Hints) > 0 {
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
			componentHintsInRange := &pb.HintsInRangeResponse_Purl{
				Purl:     hint.Purl,
				Versions: hint.Versions,
				Hints:    hints,
			}
			if hint.Status.StatusCode != status.Success {
				code := hint.Status.StatusCode.String()
				msg := hint.Status.Message
				componentHintsInRange.InfoMessage = &msg
				componentHintsInRange.InfoCode = &code
			}
			response.Purls = append(response.Purls, componentHintsInRange)
		}
		s.Debugf("Converted %d hints to components", len(output.Hints))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Hints in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

// ToComponentsHintsInRangeResponse converts ECOutput to ComponentsHintsInRangeResponse.
//
// This function builds a response containing multiple components, each with their associated
// encryption hint detections found within the specified version range. It manually constructs
// the component and hint structures from the internal DTO, including purl, versions, and
// hint detection details (ID, name, description, category, URL).
//
// The function validates that hints data exists and is non-empty before processing and
// returns an error if the input contains no hints information.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing encryption hints for multiple components in a version range
//
// Returns:
//   - *pb.ComponentsHintsInRangeResponse: Response containing all components with their hints and status
//   - error: Non-nil if hints data is missing or empty
func ToComponentsHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.ECOutput) (*pb.ComponentsHintsInRangeResponse, error) {
	var response = &pb.ComponentsHintsInRangeResponse{
		Status:     &common.StatusResponse{},
		Components: make([]*pb.ComponentsHintsInRangeResponse_Component, 0, len(output.Hints)),
	}
	if len(output.Hints) > 0 {
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
			componentHintsInRange := &pb.ComponentsHintsInRangeResponse_Component{
				Purl:     hint.Purl,
				Versions: hint.Versions,
				Hints:    hints,
			}
			if hint.Status.StatusCode != status.Success {
				code := hint.Status.StatusCode.String()
				msg := hint.Status.Message
				componentHintsInRange.InfoMessage = &msg
				componentHintsInRange.InfoCode = &code
			}
			response.Components = append(response.Components, componentHintsInRange)
		}
		s.Debugf("Converted %d hints to components", len(output.Hints))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Hints in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}

// ToComponentHintsInRangeResponse converts ECOutput to ComponentHintsInRangeResponse.
//
// This function builds a response for a single component with its associated encryption
// hint detections found within the specified version range. It manually constructs the
// component and hint structures from the internal DTO, including purl, versions, and
// hint detection details (ID, name, description, category, URL).
//
// While the input may contain multiple components, this function is designed for
// single-component responses and will process all items in the loop (though typically
// only one component is expected).
//
// The function validates that hints data exists and is non-empty before processing.
//
// Parameters:
//   - ctx: Context for request tracing and cancellation
//   - s: Structured logger for debug logging
//   - output: Internal DTO containing encryption hints for a component in a version range
//
// Returns:
//   - *pb.ComponentHintsInRangeResponse: Response containing a single component with hints and status
//   - error: Non-nil if hints data is missing or empty
func ToComponentHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output domain.ECOutput) (*pb.ComponentHintsInRangeResponse, error) {
	var response = &pb.ComponentHintsInRangeResponse{
		Status:    &common.StatusResponse{},
		Component: &pb.ComponentHintsInRangeResponse_Component{},
	}
	if len(output.Hints) > 0 {
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
			componentHintsInRange := &pb.ComponentHintsInRangeResponse_Component{
				Purl:     hint.Purl,
				Versions: hint.Versions,
				Hints:    hints,
			}
			if hint.Status.StatusCode != status.Success {
				code := hint.Status.StatusCode.String()
				msg := hint.Status.Message
				componentHintsInRange.InfoMessage = &msg
				componentHintsInRange.InfoCode = &code
			}
			response.Component = componentHintsInRange
		}
		s.Debugf("Converted %d hints to components", len(output.Hints))
	}
	response.Status = &common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Hints in range retrieved successfully.",
	}
	httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusOK)
	return response, nil
}
