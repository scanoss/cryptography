package httphelpers

import (
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type EncryptionHintsResponseHelper struct {
	response interface{}
}

func NewEncryptionHintsResponseHelper(response interface{}) Response {
	return &EncryptionHintsResponseHelper{
		response: response,
	}
}

func (h EncryptionHintsResponseHelper) componentsEncryptionHintsResponseStatus(output dtos.HintsOutput) (*common.StatusResponse, int) {
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

func (h EncryptionHintsResponseHelper) componentEncryptionHintsResponseStatus(output dtos.HintsOutput) (*common.StatusResponse, int) {
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

func (h EncryptionHintsResponseHelper) DetermineResponseStatusAndHttpCode(output interface{}) (statusCode *common.StatusResponse, httpCode int) {
	switch h.response.(type) {
	case *pb.HintsResponse:
		if hintsOutput, ok := output.(dtos.HintsOutput); ok {
			return h.componentsEncryptionHintsResponseStatus(hintsOutput)
		}
	case *pb.ComponentsEncryptionHintsResponse:
		if hintsOutput, ok := output.(dtos.HintsOutput); ok {
			return h.componentsEncryptionHintsResponseStatus(hintsOutput)
		}
	case *pb.ComponentEncryptionHintsResponse:
		if hintsOutput, ok := output.(dtos.HintsOutput); ok {
			return h.componentEncryptionHintsResponseStatus(hintsOutput)
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
