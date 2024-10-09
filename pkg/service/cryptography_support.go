// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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

// convertPurlRequestInput converts a Purl Request structure into an internal Crypto Input struct.
func convertCryptoInput(s *zap.SugaredLogger, request *common.PurlRequest) (dtos.CryptoInput, error) {
	data, err := json.Marshal(request)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request input: %v", err)
		return dtos.CryptoInput{}, errors.New("problem marshalling Cryptography input")
	}
	dtoRequest, err := dtos.ParseCryptoInput(s, data)
	if err != nil {
		s.Errorf("Problem parsing Cryptography request input: %v", err)
		return dtos.CryptoInput{}, errors.New("problem parsing Cryptography input")
	}
	return dtoRequest, nil
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
func convertVersionsInRangeUsingCryptoOutput(s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.DetectionsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.DetectionsInRangeResponse{}, errors.New("problem marshalling Versions output")
	}
	var depResp pb.DetectionsInRangeResponse
	err = json.Unmarshal(data, &depResp)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.DetectionsInRangeResponse{}, errors.New("problem unmarshalling Versions output")
	}
	return &depResp, nil
}
