package httpresponsehelper

import (
	"context"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type AlgorithmInRangeResponseHelper[T any] struct {
	response T
}

// Constructor that returns the interface type
func NewAlgorithmInRangeResponseHelper[T any](response T) Response[T] {
	return &AlgorithmInRangeResponseHelper[T]{
		response: response,
	}
}

func (h AlgorithmInRangeResponseHelper[T]) algorithmsInRangeResponseStatus(output dtos.CryptoInRangeOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmInRangeResponseHelper[T]) componentAlgorithmInRangeStatus(output dtos.CryptoInRangeOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmInRangeResponseHelper[T]) WithStatus(ctx context.Context, s *zap.SugaredLogger, output interface{}) (response T) {
	statusResponse := &common.StatusResponse{
		Status:  common.StatusCode_FAILED,
		Message: ResponseMessageError,
	}
	httpCode := http.StatusInternalServerError
	cryptoOutput, ok := output.(dtos.CryptoInRangeOutput)
	if !ok {
		SetHTTPCodeOnTrailer(ctx, s, httpCode)
		return h.response
	}
	switch resp := any(h.response).(type) {
	case *pb.AlgorithmsInRangeResponse:
		statusResponse, httpCode = h.algorithmsInRangeResponseStatus(cryptoOutput)
		resp.Status = statusResponse
	case *pb.ComponentsAlgorithmsInRangeResponse:
		statusResponse, httpCode = h.algorithmsInRangeResponseStatus(cryptoOutput)
		resp.Status = statusResponse
	case *pb.ComponentAlgorithmsInRangeResponse:
		statusResponse, httpCode = h.componentAlgorithmInRangeStatus(cryptoOutput)
		resp.Status = statusResponse
	}
	SetHTTPCodeOnTrailer(ctx, s, httpCode)
	return h.response
}
