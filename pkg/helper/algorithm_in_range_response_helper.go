package helper

import (
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type AlgorithmInRangeResponseHelper struct {
	response interface{}
}

// Constructor that returns the interface type
func NewAlgorithmInRangeResponseHelper(response interface{}) Response {
	return &AlgorithmInRangeResponseHelper{
		response: response,
	}
}

func (h AlgorithmInRangeResponseHelper) algorithmsInRangeResponseStatus(output dtos.CryptoInRangeOutput) (*common.StatusResponse, int) {
	total := len(output.Cryptography)
	malformed := 0
	withOutInfo := 0
	notFound := 0

	for _, c := range output.Cryptography {
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

func (h AlgorithmInRangeResponseHelper) componentAlgorithmInRangeStatus(output dtos.CryptoInRangeOutput) (*common.StatusResponse, int) {
	malformed := 0
	withOutInfo := 0
	notFound := 0
	for _, c := range output.Cryptography {
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

func (h AlgorithmInRangeResponseHelper) DetermineResponseStatusAndHttpCode(output interface{}) (*common.StatusResponse, int) {
	switch h.response.(type) {
	case *pb.AlgorithmsInRangeResponse:
		if cryptoOutput, ok := output.(dtos.CryptoInRangeOutput); ok {
			return h.algorithmsInRangeResponseStatus(cryptoOutput)
		}
	case *pb.ComponentsAlgorithmsInRangeResponse:
		if cryptoOutput, ok := output.(dtos.CryptoInRangeOutput); ok {
			return h.algorithmsInRangeResponseStatus(cryptoOutput)
		}
	case *pb.ComponentAlgorithmsInRangeResponse:
		if cryptoOutput, ok := output.(dtos.CryptoInRangeOutput); ok {
			return h.componentAlgorithmInRangeStatus(cryptoOutput)
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
