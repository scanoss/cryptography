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

// ToAlgorithmResponse converts an internal Crypto Output structure into a Crypto Response struct.
func ToAlgorithmResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.AlgorithmResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.AlgorithmResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		return &pb.AlgorithmResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	response = *httpresponsehelper.NewAlgorithmResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil

}

// ToComponentsAlgorithmsResponse converts an internal Crypto Output structure into a ComponentsAlgorithmsResponse.
func ToComponentsAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentsAlgorithmsResponse, error) {
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
	response = httpresponsehelper.NewAlgorithmResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

// ToComponentAlgorithmsResponse converts CryptoOutput into a ComponentsAlgorithmsResponse.
func ToComponentAlgorithmsResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.CryptoOutput) (*pb.ComponentAlgorithmsResponse, error) {
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
	response = httpresponsehelper.NewAlgorithmResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
