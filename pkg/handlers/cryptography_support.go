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
	"encoding/json"
	"errors"
	"strings"

	common "github.com/scanoss/papi/api/commonv2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
)

// metricsCounters stores OpenTelemetry metrics for the handlers package.
//
// This structure holds metric instruments used to record telemetry data
// about handler performance and request processing times.
type metricsCounters struct {
	cryptoAlgorithmsHistogram metric.Int64Histogram // Histogram for recording crypto algorithms request times in milliseconds
	downloadRulesetHistogram  metric.Int64Histogram // Histogram for recording ruleset download request times in milliseconds
	downloadRulesetCounter    metric.Int64Counter   // Counter for tracking the number of downloaded rulesets
}

var oltpMetrics = metricsCounters{}

// SetupMetrics configures all OpenTelemetry metric instruments for the handlers package.
//
// This function initializes histogram metrics for tracking request durations.
// It should be called once during handler initialization to set up the metrics infrastructure.
func SetupMetrics() {
	meter := otel.Meter("scanoss.com/cryptography")
	oltpMetrics.cryptoAlgorithmsHistogram, _ = meter.Int64Histogram("crypto.algorithms.req_time", metric.WithDescription("The time taken to run a crypto algorithms request (ms)"))
	oltpMetrics.downloadRulesetHistogram, _ = meter.Int64Histogram("crypto.rulesets.download_time", metric.WithDescription("The time taken to download a ruleset (ms)"))
	oltpMetrics.downloadRulesetCounter, _ = meter.Int64Counter("crypto.rulesets.downloaded", metric.WithDescription("The number of downloaded rulesets"))
}

// ConvertPurlRequestToComponentDTO converts a legacy PurlRequest to ComponentDTO slice.
//
// This function supports the deprecated PurlRequest format by transforming it into
// the internal ComponentDTO representation. It marshals the request to JSON and
// parses it into the DTO format.
//
// Deprecated: This function supports legacy API compatibility and should not be used
// for new code. Use convertComponentsRequestToComponentDTO for the current API format.
// This function will be removed when the legacy PurlRequest format is fully deprecated.
//
// Parameters:
//   - s: Structured logger for error logging
//   - request: Legacy PurlRequest containing purl and requirement information
//
// Returns:
//   - []dtos.ComponentDTO: Slice of converted component DTOs
//   - error: Non-nil if marshalling or parsing fails
func ConvertPurlRequestToComponentDTO(s *zap.SugaredLogger, request *common.PurlRequest) ([]dtos.ComponentDTO, error) {
	data, err := json.Marshal(request)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request input: %v", err)
		return []dtos.ComponentDTO{}, errors.New("problem marshalling Cryptography input")
	}
	dtoRequest, err := dtos.ParseCryptoInput(s, data)
	if err != nil {
		s.Errorf("Problem parsing Cryptography request input: %v", err)
		return []dtos.ComponentDTO{}, errors.New("problem parsing Cryptography input")
	}
	components := make([]dtos.ComponentDTO, 0, len(dtoRequest.Purls))
	for _, req := range dtoRequest.Purls {
		components = append(components, buildComponentDTO(req.Purl, req.Requirement))
	}
	if len(components) == 0 {
		return []dtos.ComponentDTO{}, errors.New("no components found in request")
	}
	return components, nil
}

// buildComponentDTO creates a ComponentDTO from a PURL string and requirement specification.
//
// This function constructs an internal ComponentDTO by parsing the purl and requirement.
// If the purl contains a version (e.g., "pkg:npm/foo@1.0.0"), it extracts the version
// and uses it as the requirement. Otherwise, it uses the provided requirement parameter.
//
// Parameters:
//   - purl: Package URL string, optionally including version with @ separator
//   - requirement: Version requirement specification (e.g., "^4.17.0", ">=1.0.0")
//
// Returns:
//   - dtos.ComponentDTO: Internal component representation with purl, version, and requirement
func buildComponentDTO(purl string, requirement string) dtos.ComponentDTO {
	p := purl
	req := requirement
	purlParts := strings.Split(purl, "@")
	if len(purlParts) > 1 {
		p = purlParts[0]
		req = purlParts[1]
	}

	return dtos.ComponentDTO{
		// map fields appropriately
		Purl:        p,
		Version:     req,
		Requirement: req,
	}
}

// convertComponentsRequestToComponentDTO converts a ComponentsRequest to a slice of ComponentDTO.
//
// This function transforms the gRPC ComponentsRequest format into internal ComponentDTO
// representations. It validates that the request and components are non-nil and non-empty,
// then converts each component using buildComponentDTO.
//
// Parameters:
//   - request: ComponentsRequest containing multiple component specifications
//
// Returns:
//   - []dtos.ComponentDTO: Slice of converted component DTOs
//   - error: Non-nil if request is nil, components are nil, or components array is empty
func convertComponentsRequestToComponentDTO(request *common.ComponentsRequest) ([]dtos.ComponentDTO, error) {
	if request == nil || request.Components == nil {
		return nil, errors.New("'components' field is required but was not provided")
	}
	var components []dtos.ComponentDTO
	if len(request.Components) == 0 {
		return nil, errors.New("'components' array cannot be empty, at least one component must be provided")
	}
	for _, req := range request.Components {
		components = append(components, buildComponentDTO(req.Purl, req.Requirement))
	}
	return components, nil
}

// validateComponentRequest validates that a ComponentRequest contains required fields.
//
// This function ensures that the request is non-nil and contains a non-empty purl field.
// It is used as a guard clause before processing single component requests.
//
// Parameters:
//   - request: ComponentRequest to validate
//
// Returns:
//   - error: Non-nil if request is nil or purl is empty, nil if validation passes
func validateComponentRequest(request *common.ComponentRequest) error {
	if request == nil || request.Purl == "" {
		return errors.New("no purl supplied. A PURL is required")
	}
	return nil
}

// validateComponentRequestRange validates that a ComponentRequest contains required fields.
//
// This function ensures that the request is non-nil and contains a non-empty purl field.
// It is used as a guard clause before processing single component requests.
//
// Parameters:
//   - request: ComponentRequest to validate
//
// Returns:
//   - error: Non-nil if request is nil or purl is empty, nil if validation passes
func validateComponentRequestRange(request *common.ComponentRequest) error {
	if request == nil || request.Purl == "" {
		return errors.New("no purl supplied. A PURL is required")
	}
	if request.Requirement == "" {
		return errors.New("no requirement supplied. A requirement is required")
	}
	return nil
}
