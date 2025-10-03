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

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"scanoss.com/cryptography/pkg/helper"
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

// ConvertCryptoOutput converts an internal Crypto Output structure into a Crypto Response struct.
func ConvertCryptoOutput(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.AlgorithmResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.AlgorithmResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	h := helper.NewAlgorithmResponseHelper(&response)
	status, _ := h.DetermineResponseStatusAndHttpCode(output)
	response.Status = status
	return &response, nil
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

// convertCryptoOutputToComponents converts an internal Crypto Output structure
// into a ComponentsAlgorithmsResponse.
func convertCryptoOutputToComponents(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentsAlgorithmsResponse, error) {
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
	h := helper.NewAlgorithmResponseHelper(response)
	status, httpCode := h.DetermineResponseStatusAndHttpCode(output)
	setHTTPCodeOnTrailer(ctx, s, httpCode)
	response.Status = status
	return response, nil
}

// into a ComponentsAlgorithmsResponse.
func convertCryptoOutputToComponent(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentAlgorithmsResponse, error) {
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
	h := helper.NewAlgorithmResponseHelper(response)
	status, httpCode := h.DetermineResponseStatusAndHttpCode(output)
	setHTTPCodeOnTrailer(ctx, s, httpCode)
	response.Status = status
	return response, nil
}

// convertComponentsCryptoInRangeOutput converts an internal Crypto Range Output to ComponentsAlgorithmsInRangeResponse.
func convertComponentsCryptoInRangeOutput(s *zap.SugaredLogger, output dtos.CryptoInRangeOutput) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
	s.Debugf("convertComponentsCryptoInRangeOutput: %v", output)
	if (output.Cryptography == nil) || (len(output.Cryptography) == 0) {
		return nil, errors.New("no cryptography found")
	}
	var response = &pb.ComponentsAlgorithmsInRangeResponse{
		Components: make([]*pb.ComponentsAlgorithmsInRangeResponse_Component, 0),
		Status:     &common.StatusResponse{},
	}
	for i, c := range output.Cryptography {
		var algorithms = make([]*pb.Algorithm, 0, len(output.Cryptography[i].Algorithms))
		for _, alg := range c.Algorithms {
			algorithms = append(algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
		response.Components = append(response.Components, &pb.ComponentsAlgorithmsInRangeResponse_Component{
			Purl:       output.Cryptography[i].Purl,
			Versions:   output.Cryptography[i].Versions,
			Algorithms: algorithms,
		})
	}
	return response, nil
}

// convertToComponentsVersionInRangeOutput converts an internal VersionsInRange Output structure into a ComponentsVersionsInRangeResponse struct.
func convertToComponentsVersionInRangeOutput(s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.ComponentsVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	if (output.Versions == nil) || (len(output.Versions) == 0) {
		return nil, errors.New("no versions found")
	}
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
	return response, nil
}

// convertToComponentsHintsInRangeOutput converts an internal Crypto in Major Output structure into a Crypto Response struct.
func convertToComponentsHintsInRangeOutput(s *zap.SugaredLogger, output dtos.ECOutput) (*pb.ComponentsHintsInRangeResponse, error) {
	if (output.Hints == nil) || (len(output.Hints) == 0) {
		return nil, errors.New("no hints found")
	}
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
			component := &pb.ComponentsHintsInRangeResponse_Component{
				Purl:     hint.Purl,
				Versions: hint.Versions,
				Hints:    hints,
			}
			response.Components = append(response.Components, component)
		}
		s.Debugf("Converted %d hints to components", len(output.Hints))
	}
	return response, nil
}

// convertEncryptionHintsToComponentsEncryptionOutput converts internal HintsOutput to ComponentsEncryptionHintsResponse.
func convertEncryptionHintsToComponentsEncryptionOutput(output dtos.HintsOutput) (*pb.ComponentsEncryptionHintsResponse, error) {
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
