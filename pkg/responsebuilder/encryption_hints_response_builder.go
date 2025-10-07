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

// ToHintsResponse converts an internal Crypto in Major Output structure into a Crypto Response struct.
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
	response = *httpresponsehelper.NewEncryptionHintsResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil
}

// ToComponentsEncryptionHintsResponse converts internal HintsOutput to ComponentsEncryptionHintsResponse.
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
	response = httpresponsehelper.NewEncryptionHintsResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

// ToComponentEncryptionHintsResponse converts internal HintsOutput to ComponentsEncryptionHintsResponse.
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
	response = httpresponsehelper.NewEncryptionHintsResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
