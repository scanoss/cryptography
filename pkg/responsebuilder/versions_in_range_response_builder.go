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

// ToVersionsInRangeResponse converts an internal VersionsInRange Output structure into a DetectionsInRangeResponse struct.
func ToVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.VersionsInRangeResponse, error) {
	data, err := json.Marshal(output)
	if err != nil {
		s.Errorf("Problem marshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem marshalling Versions output")
	}
	var response pb.VersionsInRangeResponse
	err = json.Unmarshal(data, &response)
	if err != nil {
		s.Errorf("Problem unmarshalling Cryptography request output: %v", err)
		return &pb.VersionsInRangeResponse{}, errors.New("problem unmarshalling Versions output")
	}
	response = *httpresponsehelper.NewVersionsInRangeResponseHelper(&response).WithStatus(ctx, s, output)
	return &response, nil
}

// ToComponentsVersionsInRangeResponse converts an internal VersionsInRange Output structure into a ComponentsVersionsInRangeResponse struct.
func ToComponentsVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.ComponentsVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
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
	response = httpresponsehelper.NewVersionsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}

// ToComponentVersionsInRangeResponse converts an internal VersionsInRange Output structure into a ComponentsVersionsInRangeResponse struct.
func ToComponentVersionsInRangeResponse(ctx context.Context, s *zap.SugaredLogger, output dtos.VersionsInRangeOutput) (*pb.ComponentVersionsInRangeResponse, error) {
	s.Debugf("convertToComponentsVersionInRangeOutput: %v", output)
	if (output.Versions == nil) || (len(output.Versions) == 0) {
		return nil, errors.New("no versions found")
	}
	var response = &pb.ComponentVersionsInRangeResponse{
		Component: &pb.ComponentVersionsInRangeResponse_Component{},
		Status:    &common.StatusResponse{},
	}
	for _, v := range output.Versions {
		response.Component = &pb.ComponentVersionsInRangeResponse_Component{
			Purl:            v.Purl,
			VersionsWith:    v.VersionsWith,
			VersionsWithout: v.VersionsWithout,
		}
	}
	response = httpresponsehelper.NewVersionsInRangeResponseHelper(response).WithStatus(ctx, s, output)
	return response, nil
}
