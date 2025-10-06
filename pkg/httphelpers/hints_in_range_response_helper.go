package httphelpers

import (
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type HintsInRangeResponseHelper struct {
	response interface{}
}

// Constructor that returns the interface type
func NewHintsInRangeResponseHelper(response interface{}) Response {
	return &HintsInRangeResponseHelper{
		response: response,
	}
}

func (h HintsInRangeResponseHelper) componentsHintsInRangeResponseStatus(output dtos.ECOutput) (*common.StatusResponse, int) {
	total := len(output.Hints)
	malformed := 0
	withOutInfo := 0
	notFound := 0
	for _, c := range output.Hints {
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

func (h HintsInRangeResponseHelper) componentHintsInRangeResponseStatus(output dtos.ECOutput) (*common.StatusResponse, int) {
	malformed := 0
	withOutInfo := 0
	notFound := 0
	for _, c := range output.Hints {
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

func (h HintsInRangeResponseHelper) DetermineResponseStatusAndHttpCode(output interface{}) (statusCode *common.StatusResponse, httpCode int) {
	switch h.response.(type) {
	case *pb.HintsInRangeResponse:
		if hintsInRangeOutput, ok := output.(dtos.ECOutput); ok {
			return h.componentsHintsInRangeResponseStatus(hintsInRangeOutput)
		}
	case *pb.ComponentsHintsInRangeResponse:
		if hintsInRangeOutput, ok := output.(dtos.ECOutput); ok {
			return h.componentsHintsInRangeResponseStatus(hintsInRangeOutput)
		}
	case *pb.ComponentHintsInRangeResponse:
		if hintsInRangeOutput, ok := output.(dtos.ECOutput); ok {
			return h.componentHintsInRangeResponseStatus(hintsInRangeOutput)
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
