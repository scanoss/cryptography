package handler

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

type AlgorithmInRangeHandler struct {
	CryptoMajorUseCase usecase.CryptoMajorUseCase
}

// NewCryptographyAlgorithmHandler creates a new instance of Cryptography Server.
func NewAlgorithmInRangeHandler(db *sqlx.DB, config *myconfig.ServerConfig) *AlgorithmInRangeHandler {
	//setupMetrics()
	return &AlgorithmInRangeHandler{
		CryptoMajorUseCase: *usecase.NewCryptoMajor(db, config),
	}
}

func (c AlgorithmInRangeHandler) GetAlgorithmsInRange(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmsInRangeResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}

	output, err := c.CryptoMajorUseCase.GetCryptoInRange(ctx, s, dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, nil
	}

	response, err := convertCryptoMajorOutput(s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'AlgorithmsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	return response, nil
}

func (c AlgorithmInRangeHandler) GetComponentsAlgorithmsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
	// requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	dtos, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsAlgorithmsInRangeResponse {
			return &pb.ComponentsAlgorithmsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	// Search the KB for information about each Cryptography
	output, err := c.CryptoMajorUseCase.GetCryptoInRange(ctx, s, dtos)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	fmt.Printf("OUTPUT: %v\n", output)
	response, err := convertComponentsCryptoInRangeOutput(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms in range to 'ComponentsAlgorithmsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems converting algorithms to response"}
		return &pb.ComponentsAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c AlgorithmInRangeHandler) GetComponentAlgorithmsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsInRangeResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing component algorithms request...")
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentAlgorithmsInRangeResponse {
			return &pb.ComponentAlgorithmsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	// Search the KB for information about each Cryptography
	output, err := c.CryptoMajorUseCase.GetCryptoInRange(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)

		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	response, err := convertComponentCryptoInRangeOutput(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms in range to 'ComponentsAlgorithmsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems converting algorithms to response"}
		return &pb.ComponentAlgorithmsInRangeResponse{Status: &statusResp}, nil
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil

}
