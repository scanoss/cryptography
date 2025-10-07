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

type HintsRangeHandler struct {
	hintsInRangeUseCase usecase.ECDetectionUseCase
}

// NewHintsInRangeHandler creates a new instance of HintsRangeHandler.
func NewHintsInRangeHandler(db *sqlx.DB, config *myconfig.ServerConfig) *HintsRangeHandler {
	//setupMetrics()
	return &HintsRangeHandler{
		hintsInRangeUseCase: *usecase.NewECDetection(db, config),
	}
}

func (c HintsRangeHandler) GetHintsInRange(ctx context.Context, request *common.PurlRequest) (*pb.HintsInRangeResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// Make sure we have Cryptography data to query
	reqPurls := request.GetPurls()
	if len(reqPurls) == 0 {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "No purls in request data supplied"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("no purl data supplied")
	}
	dtoRequest, err := ConvertPurlRequestToComponentDTO(s, request) // Convert to internal DTO for processing
	if err != nil {
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problem parsing Cryptography input data"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing Cryptography input data")
	}
	// Search the KB for information about each Cryptography
	output, err := c.hintsInRangeUseCase.GetDetectionsInRange(ctx, s, dtoRequest)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem encountered extracting Cryptography data")
	}

	response, err := responsebuilder.ToHintsInRangeResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert hints in range to 'HintsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.HintsInRangeResponse{Status: &statusResp}, errors.New("problem parsing cryptography data")
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c HintsRangeHandler) GetComponentsHintsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsHintsInRangeResponse, error) {
	//requestStartTime := time.Now() // Capture the scan start time
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing crypto algorithms request...")
	// handle request
	dto, errorResp := rejectIfInvalidComponents(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentsHintsInRangeResponse {
			return &pb.ComponentsHintsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}
	// Search the KB for information about each Cryptography
	output, err := c.hintsInRangeUseCase.GetDetectionsInRange(ctx, s, dto)
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problem encountered extracting Cryptography data")
	}
	fmt.Printf("OUTPUT: %v\n", output)
	response, err := responsebuilder.ToComponentsHintsInRangeResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert hints in range to 'ComponentsHintsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentsHintsInRangeResponse{Status: &statusResp}, errors.New("problems getting hints in range")
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil
}

func (c HintsRangeHandler) GetComponentHintsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentHintsInRangeResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Info("Processing component to get hints in range...")
	errorResp := rejectIfInvalid(ctx, s, request,
		func(status *common.StatusResponse) *pb.ComponentHintsInRangeResponse {
			return &pb.ComponentHintsInRangeResponse{Status: status}
		})
	if errorResp != nil {
		return errorResp, nil
	}

	output, err := c.hintsInRangeUseCase.GetDetectionsInRange(ctx, s, []dtos.ComponentDTO{{Purl: request.Purl, Requirement: request.Requirement}})
	if err != nil {
		s.Errorf("Failed to get cryptographic algorithms: %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: fmt.Sprintf("%v", err)}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("problem encountered extracting Cryptography data")
	}
	response, err := responsebuilder.ToComponentHintsInRangeResponse(ctx, s, output) // Convert the internal data into a response object
	if err != nil {
		s.Errorf("Failed to convert hints in range to 'ComponentsHintsInRangeResponse': %v", err)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: "Problems encountered extracting Cryptography data"}
		return &pb.ComponentHintsInRangeResponse{Status: &statusResp}, errors.New("problems getting hints in range")
	}
	//telemetryRequestTime(ctx, c.config, requestStartTime)
	return response, nil

}
