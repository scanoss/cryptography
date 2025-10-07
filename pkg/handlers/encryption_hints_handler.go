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
	"scanoss.com/cryptography/pkg/responsebuilder"
	"scanoss.com/cryptography/pkg/usecase"
)

type EncryptionHintsHandler struct {
	encryptionHintsUseCase usecase.ECDetectionUseCase
}

// NewEncryptionHintsHandler creates a new instance of EncryptionHintsHandler.
func NewEncryptionHintsHandler(db *sqlx.DB, config *myconfig.ServerConfig) *EncryptionHintsHandler {
	//setupMetrics()
	return &EncryptionHintsHandler{
		encryptionHintsUseCase: *usecase.NewECDetection(db, config),
	}
}

func (c EncryptionHintsHandler) GetEncryptionHints(ctx context.Context, request *common.PurlRequest) (*pb.HintsResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing Crypto hints algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dto, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	output, err := c.encryptionHintsUseCase.GetDetections(ctx, s, dto)
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	response, err := responsebuilder.ToHintsResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert encryption hints to 'HintsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.HintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	//	telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c EncryptionHintsHandler) GetComponentsEncryptionHints(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsEncryptionHintsResponse, error) {
	// requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing Crypto hints algorithms request...")
	// handle request
	dto, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsEncryptionHintsResponse {
			return &pb.ComponentsEncryptionHintsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}

	output, err := c.encryptionHintsUseCase.GetDetections(ctx, s, dto)
	fmt.Printf("OUTPUT: %v\n", output)
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}

	response, err := responsebuilder.ToComponentsEncryptionHintsResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert encryption hints to 'ComponentsEncryptionHintsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c EncryptionHintsHandler) GetComponentEncryptionHints(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentEncryptionHintsResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing component to get encryption hints...")
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentEncryptionHintsResponse {
			return &pb.ComponentEncryptionHintsResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	output, err := c.encryptionHintsUseCase.GetDetections(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get encryption hints: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}

	response, err := responsebuilder.ToComponentEncryptionHintsResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert encryption hints to 'ComponentsEncryptionHintsResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentEncryptionHintsResponse{Status: &statusResp}, errors.New("problems getting encryption hints")
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}
