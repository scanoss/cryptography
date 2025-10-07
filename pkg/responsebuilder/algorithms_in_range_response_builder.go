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

// ToAlgorithmsInRangeResponse converts an internal Crypto in Major Output structure into a Crypto Response struct.
func ToAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoInRangeOutput) (*pb.AlgorithmsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.AlgorithmsInRangeResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.AlgorithmsInRangeResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	response = *httpresponsehelper.NewAlgorithmInRangeResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil
}

// ToComponentsAlgorithmsInRangeResponse converts an internal Crypto Range Output to ComponentsAlgorithmsInRangeResponse.
func ToComponentsAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoInRangeOutput) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
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
	response = httpresponsehelper.NewAlgorithmInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

func ToComponentAlgorithmsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoInRangeOutput) (*pb.ComponentAlgorithmsInRangeResponse, error) {
	s.Debugf("convertComponentsCryptoInRangeOutput: %v", output)
	if (output.Cryptography == nil) || (len(output.Cryptography) == 0) {
		return nil, errors.New("no cryptography found")
	}
	var response = &pb.ComponentAlgorithmsInRangeResponse{
		Component: &pb.ComponentAlgorithmsInRangeResponse_Component{},
		Status:    &common.StatusResponse{},
	}
	for i, c := range output.Cryptography {
		var algorithms = make([]*pb.Algorithm, 0, len(output.Cryptography[i].Algorithms))
		for _, alg := range c.Algorithms {
			algorithms = append(algorithms, &pb.Algorithm{
				Algorithm: alg.Algorithm,
				Strength:  alg.Strength,
			})
		}
		response.Component = &pb.ComponentAlgorithmsInRangeResponse_Component{
			Purl:       output.Cryptography[i].Purl,
			Versions:   output.Cryptography[i].Versions,
			Algorithms: algorithms,
		}
	}
	response = httpresponsehelper.NewAlgorithmInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
