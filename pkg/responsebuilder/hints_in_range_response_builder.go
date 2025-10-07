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

// ToHintsInRangeResponse converts an internal Crypto in Major Output structure into a Crypto Response struct.
func ToHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.ECOutput) (*pb.HintsInRangeResponse, error) {
	data, err := json.Marshal(output)

	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.HintsInRangeResponse{}, errors.New("problem marshalling Cryptography output")
	}
	var response pb.HintsInRangeResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.HintsInRangeResponse{}, errors.New("problem unmarshalling Cryptography output")
	}
	response = *httpresponsehelper.NewHintsInRangeResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil
}

// ToComponentsHintsInRangeResponse converts an internal Crypto in Major Output structure into a Crypto Response struct.
func ToComponentsHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.ECOutput) (*pb.ComponentsHintsInRangeResponse, error) {
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
	response = httpresponsehelper.NewHintsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

// ToComponentHintsInRangeResponse converts an internal Crypto in Major Output structure into a Crypto Response struct.
func ToComponentHintsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.ECOutput) (*pb.ComponentHintsInRangeResponse, error) {
	if (output.Hints == nil) || (len(output.Hints) == 0) {
		return nil, errors.New("no hints found")
	}
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
			response.Component = &pb.ComponentHintsInRangeResponse_Component{
				Purl:     hint.Purl,
				Versions: hint.Versions,
				Hints:    hints,
			}
		}
		s.Debugf("Converted %d hints to components", len(output.Hints))
	}
	response = httpresponsehelper.NewHintsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
