package helper

import (
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type AlgorithmResponseHelper struct {
	response interface{}
}

func NewAlgorithmResponseHelper(response interface{}) Response {
	return &AlgorithmResponseHelper{
		response: response,
	}
}

func (h AlgorithmResponseHelper) algorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmResponseHelper) componentAlgorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmResponseHelper) DetermineResponseStatusAndHttpCode(output interface{}) (*common.StatusResponse, int) {
	switch h.response.(type) {
	case *pb.AlgorithmResponse:
		if cryptoOutput, ok := output.(dtos.CryptoOutput); ok {
			return h.algorithmsResponseStatus(cryptoOutput)
		}
	case *pb.ComponentsAlgorithmsResponse:
		if cryptoOutput, ok := output.(dtos.CryptoOutput); ok {
			return h.algorithmsResponseStatus(cryptoOutput)
		}
	case *pb.ComponentAlgorithmsResponse:
		if cryptoOutput, ok := output.(dtos.CryptoOutput); ok {
			return h.componentAlgorithmsResponseStatus(cryptoOutput)
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
