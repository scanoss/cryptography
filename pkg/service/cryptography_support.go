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

package service

import (
	"encoding/json"
	"errors"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
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

// convertPurlRequestInput converts a Purl Request structure into an internal Crypto Input struct. TODO: Remove this method when legacy request be removed
func convertPurlRequestToComponentDTO(s *zap.SugaredLogger, request *common.PurlRequest) ([]dtos.ComponentDTO, error) {
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

// convertCryptoOutput converts an internal Crypto Output structure into a Crypto Response struct.
func convertCryptoOutput(s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.AlgorithmResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.AlgorithmResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var depResp pb.AlgorithmResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.AlgorithmResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	return &depResp, nil
}

// convertCryptoOutput converts an internal Crypto in Major Output structure into a Crypto Response struct.
func convertCryptoMajorOutput(s *zap.SugaredLogger, output dtos.CryptoInRangeOutput) (*pb.AlgorithmsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var depResp pb.AlgorithmsInRangeResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	return &depResp, nil
}

// convertVersionsInRangeUsingCryptoOutput converts an internal VersionsInRange Output structure into a DetectionsInRangeResponse struct.
func convertVersionsInRangeUsingCryptoOutput(s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.VersionsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem marshalling Versions output")
	}
	var depResp pb.VersionsInRangeResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem unmarshalling Versions output")
	}
	return &depResp, nil
}

// convertCryptoOutput converts an internal Crypto in Major Output structure into a Crypto Response struct.
func convertECOutput(s *zap.SugaredLogger, output dtos.ECOutput) (*pb.HintsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.HintsInRangeResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var depResp pb.HintsInRangeResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.HintsInRangeResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	return &depResp, nil
}

// convertCryptoOutput converts an internal Crypto in Major Output structure into a Crypto Response struct.
func convertHintsOutput(s *zap.SugaredLogger, output dtos.HintsOutput) (*pb.HintsResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.HintsResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var depResp pb.HintsResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.HintsResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	return &depResp, nil
}

// buildComponentDTO creates a ComponentDTO from a PURL string and requirement specification
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

// convertComponentsRequestToComponentDTO converts a ComponentsRequest to a slice of ComponentDTO
func convertComponentsRequestToComponentDTO(request *common.ComponentsRequest) ([]dtos.ComponentDTO, error) {
	var components []dtos.ComponentDTO
	if len(request.Components) <= 0 {
		return nil, errors.New("no components supplied")
	}
	for _, req := range request.Components {
		components = append(components, buildComponentDTO(req.Purl, req.Requirement))
	}
	return components, nil
}

// convertComponentRequestToComponentDTO converts a single ComponentRequest to ComponentDTO
func convertComponentRequestToComponentDTO(request *common.ComponentRequest) (dtos.ComponentDTO, error) {
	componentDTO, err := convertComponentsRequestToComponentDTO(&common.ComponentsRequest{
		Components: []*common.ComponentRequest{request},
	})
	return componentDTO[0], err
}

// cryptoOutputToComponentsAlgorithmsResponse converts an internal Crypto Output structure
// into a ComponentsAlgorithmsResponse.
func cryptoOutputToComponentsAlgorithmsResponse(s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentsAlgorithmsResponse, error) {
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
	return response, nil
}

// cryptoOutputToComponentAlgorithmsResponse converts an internal Crypto Output structure
// into a ComponentAlgorithmsResponse for single component queries.
func cryptoOutputToComponentAlgorithmsResponse(s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentAlgorithmsResponse, error) {
	response := &pb.ComponentAlgorithmsResponse{
		Component: &pb.ComponentAlgorithms{
			Purl:        output.Cryptography[0].Purl,
			Version:     output.Cryptography[0].Version,
			Requirement: output.Cryptography[0].Requirement,
			Algorithms:  make([]*pb.Algorithm, 0, len(output.Cryptography[0].Algorithms)),
		},
		Status: &common.StatusResponse{},
	}
	for _, component := range output.Cryptography {
		for _, alg := range component.Algorithms {
			response.Component.Algorithms = append(response.Component.Algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
	}
	return response, nil
}
