package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/usecase"
)

type VersionsInRangeHandler struct {
	versionInRangeUseCase usecase.VersionsUsingCrypto
}

// NewVersionsInRangeHandler creates a new instance of Cryptography Server.
func NewVersionsInRangeHandler(db *sqlx.DB, config *myconfig.ServerConfig) *VersionsInRangeHandler {
	//setupMetrics()
	return &VersionsInRangeHandler{
		versionInRangeUseCase: *usecase.NewVersionsUsingCrypto(db, config),
	}
}

func (c VersionsInRangeHandler) GetVersionsInRange(ctx context.Context, request *common.PurlRequest) (*pb.VersionsInRangeResponse, error) {
	// requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	componentDTOS, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}

	dtoCrypto, err := c.versionInRangeUseCase.GetVersionsInRangeUsingCrypto(ctx, s, componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, nil
	}

	response, err := convertVersionsInRangeUsingCryptoOutput(s, dtoCrypto) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert versions in range to 'VersionsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.VersionsInRangeResponse{Status: &statusResp}, nil
	}
	// response.Status = statusResp
	// telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c VersionsInRangeHandler) GetComponentsVersionsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsVersionsInRangeResponse, error) {
	// requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	// TODO: Use common module for errors
	componentDTOS, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsVersionsInRangeResponse {
			return &pb.ComponentsVersionsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}

	output, err := c.versionInRangeUseCase.GetVersionsInRangeUsingCrypto(ctx, s, componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, nil
	}

	response, err := convertToComponentsVersionInRangeOutput(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert versions in range to 'ComponentsVersionsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsVersionsInRangeResponse{Status: &statusResp}, nil
	}
	// telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c VersionsInRangeHandler) GetComponentVersionsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentVersionsInRangeResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing component to get versions in range...")
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentVersionsInRangeResponse {
			return &pb.ComponentVersionsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	output, err := c.versionInRangeUseCase.GetVersionsInRangeUsingCrypto(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, nil
	}

	response, err := convertToComponentVersionInRangeOutput(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert versions in range to 'ComponentsVersionsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentVersionsInRangeResponse{Status: &statusResp}, nil
	}
	// telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}
