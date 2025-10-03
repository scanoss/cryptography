package handler

import (
	"context"
	"errors"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/usecase"
)

type CryptographyAlgorithmHandler struct {
	cryptoUseCase usecase.CryptoUseCase
}

// NewCryptographyAlgorithmHandler creates a new instance of Cryptography Server.
func NewCryptographyAlgorithmHandler(db *sqlx.DB, config *myconfig.ServerConfig) *CryptographyAlgorithmHandler {
	//setupMetrics()
	return &CryptographyAlgorithmHandler{
		cryptoUseCase: *usecase.NewCrypto(db, config),
	}
}

// Deprecated: use GetComponentsAlgorithms instead.
func (c CryptographyAlgorithmHandler) GetAlgorithms(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}

	componentCrypto, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, dtoRequest)
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'AlgorithmResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: &statusResp}, nil
	}

	response, err := ConvertCryptoOutput(ctx, s, componentCrypto) // Convert the internal data into a response object
	if err != nil {
		statusResp := &common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.AlgorithmResponse{Status: statusResp}, nil
	}

	return response, nil
}

// GetComponentsAlgorithms retrieves cryptographic algorithms for multiple components.
func (c CryptographyAlgorithmHandler) GetComponentsAlgorithms(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	componentDTOS, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsAlgorithmsResponse {
			return &pb.ComponentsAlgorithmsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil // TODO: Implement status Errors gRPC status.Errorf(codes.InvalidArgument, "Bad request")
	}
	output, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, componentDTOS)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}
	response, err := convertCryptoOutputToComponents(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'ComponentsAlgorithmsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsAlgorithmsResponse{Status: &statusResp}, nil
	}
	return response, nil
}

// GetComponentAlgorithms retrieves cryptographic algorithms for multiple components.
func (c CryptographyAlgorithmHandler) GetComponentAlgorithms(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentAlgorithmsResponse {
			return &pb.ComponentAlgorithmsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	output, err := c.cryptoUseCase.GetComponentsAlgorithms(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
	}
	response, err := convertCryptoOutputToComponent(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert algorithms to 'ComponentsAlgorithmsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentAlgorithmsResponse{Status: &statusResp}, nil
	}
	//handler.telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil

}
