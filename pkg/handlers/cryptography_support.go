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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	common "github.com/scanoss/papi/api/commonv2"
	"scanoss.com/cryptography/pkg/dtos"
)

// Structure for storing OTEL metrics.
type metricsCounters struct {
	cryptoAlgorithmsHistogram metric.Int64Histogram // milliseconds
}

var oltpMetrics = metricsCounters{}

// setupMetrics configures all the metrics recorders for the platform.
func setupMetrics() {
	meter := otel.Meter("scanoss.com/cryptography")
	oltpMetrics.cryptoAlgorithmsHistogram, _ = meter.Int64Histogram("crypto.algorithms.req_time", metric.WithDescription("The time taken to run a crypto algorithms request (ms)"))
}

// ConvertPurlRequestInput converts a Purl Request structure into an internal Crypto Input struct. TODO: Remove this method when legacy request be removed.
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
	return components, nil
}

// buildComponentDTO creates a ComponentDTO from a PURL string and requirement specification.
func buildComponentDTO(purl string, requirement string) dtos.ComponentDTO {
	p := purl
	req := requirement
	if requirement != "" {
		req = requirement
	}
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

// validateComponentRequest converts a single ComponentRequest to ComponentDTO.
func validateComponentRequest(request *common.ComponentRequest) error {
	if request == nil || request.Purl == "" {
		return errors.New("no purl supplied. A PURL is required")
	}
	return nil
}
