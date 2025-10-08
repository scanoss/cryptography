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
func ToHintsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.HintsOutput) (*pb.HintsResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.HintsResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.HintsResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.HintsResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	return &response, nil
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
func ToComponentsEncryptionHintsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.HintsOutput) (*pb.ComponentsEncryptionHintsResponse, error) {
	if output.Hints == nil {
		return nil, errors.New("no encryption hints found")
	}
	var response = &pb.ComponentsEncryptionHintsResponse{
		Components: make([]*pb.ComponentHints, 0, len(output.Hints)),
		Status:     &common.StatusResponse{},
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
		response.Components = append(response.Components, &pb.ComponentHints{
			Purl:        hint.Purl,
			Version:     hint.Version,
			Requirement: hint.Requirement,
			Hints:       hints,
		})
	}
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
func ToComponentEncryptionHintsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.HintsOutput) (*pb.ComponentEncryptionHintsResponse, error) {
	if output.Hints == nil {
		return nil, errors.New("no encryption hints found")
	}
	var response = &pb.ComponentEncryptionHintsResponse{
		Component: &pb.ComponentHints{},
		Status:    &common.StatusResponse{},
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
		response.Component = &pb.ComponentHints{
			Purl:        hint.Purl,
			Version:     hint.Version,
			Requirement: hint.Requirement,
			Hints:       hints,
		}
	}
	return response, nil
}
