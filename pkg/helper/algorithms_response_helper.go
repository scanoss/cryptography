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

func NewAlgorithmResponseHelper(response interface{}) *AlgorithmResponseHelper {
	return &AlgorithmResponseHelper{
		response: response,
	}
}

func (h AlgorithmResponseHelper) algorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK

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

	if malformed > 0 && malformed >= total {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusBadRequest
		response.Message = "Invalid purls"
		return &response, httpCode
	}

	if notFound > 0 && notFound >= total {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusNotFound
		response.Message = "not found algorithm for requested components"
		return &response, httpCode
	}

	if notFound > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Some components algorithms were not found"
	}

	if withOutInfo > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Not found info for requested components"
		return &response, httpCode
	}

	if malformed > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Some components are not valid purls"
		return &response, httpCode
	}

	return &response, httpCode
}

func (h AlgorithmResponseHelper) componentAlgorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK
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

	if malformed > 0 {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusBadRequest
		response.Message = "Bad Request"
		return &response, httpCode
	}

	if notFound > 0 {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusNotFound
		response.Message = "not found algorithm for requested components"
		return &response, httpCode
	}

	if withOutInfo > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Not found info for requested components"
		return &response, httpCode
	}

	return &response, httpCode
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
