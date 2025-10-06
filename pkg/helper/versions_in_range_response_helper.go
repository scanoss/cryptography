package helper

import (
	"fmt"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type VersionsInRangeResponseHelper struct {
	response interface{}
}

// Constructor that returns the interface type
func NewVersionsInRangeResponseHelper(response interface{}) Response {
	return &VersionsInRangeResponseHelper{
		response: response,
	}
}

func (h VersionsInRangeResponseHelper) versionsInRangeResponseStatus(output dtos.VersionsInRangeOutput) (*common.StatusResponse, int) {
	fmt.Printf("VERSIONS IN RANGE RESPONSE STATUS: %v", output.Versions)
	total := len(output.Versions)
	malformed := 0
	withOutInfo := 0
	notFound := 0
	for _, c := range output.Versions {
		switch c.Status {
		case dtos.ComponentNotFound:
			notFound++
		case dtos.ComponentMalformed:
			malformed++
		case dtos.ComponentWithoutInfo:
			withOutInfo++
		}
	}
	return determineStatusForBatchAction(malformed, withOutInfo, notFound, total)
}

func (h VersionsInRangeResponseHelper) componentVersionsInRangeResponseStatus(output dtos.VersionsInRangeOutput) (*common.StatusResponse, int) {
	malformed := 0
	withOutInfo := 0
	notFound := 0
	for _, c := range output.Versions {
		switch c.Status {
		case dtos.ComponentNotFound:
			notFound++
		case dtos.ComponentMalformed:
			malformed++
		case dtos.ComponentWithoutInfo:
			withOutInfo++
		}
	}
	return determineStatusForSingleAction(malformed, withOutInfo, notFound)
}

func (h VersionsInRangeResponseHelper) DetermineResponseStatusAndHttpCode(output interface{}) (statusCode *common.StatusResponse, httpCode int) {
	switch h.response.(type) {
	case *pb.VersionsInRangeResponse:
		if versionsInRangeOutput, ok := output.(dtos.VersionsInRangeOutput); ok {
			return h.versionsInRangeResponseStatus(versionsInRangeOutput)
		}
	case *pb.ComponentsVersionsInRangeResponse:
		if versionsInRangeOutput, ok := output.(dtos.VersionsInRangeOutput); ok {
			return h.versionsInRangeResponseStatus(versionsInRangeOutput)
		}
	case *pb.ComponentVersionsInRangeResponse:
		if versionsInRangeOutput, ok := output.(dtos.VersionsInRangeOutput); ok {
			return h.componentVersionsInRangeResponseStatus(versionsInRangeOutput)
		}
	default:
		return &common.StatusResponse{
			Status:  common.StatusCode_FAILED,
			Message: ResponseMessageError,
		}, http.StatusInternalServerError
	}
	return &common.StatusResponse{
		Status:  common.StatusCode_FAILED,
		Message: ResponseMessageError,
	}, http.StatusInternalServerError
}
