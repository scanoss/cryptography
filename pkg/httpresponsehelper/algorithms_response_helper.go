package httpresponsehelper

import (
	"context"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type AlgorithmResponseHelper[T any] struct {
	response T
}

func NewAlgorithmResponseHelper[T any](response T) Response[T] {
	return &AlgorithmResponseHelper[T]{
		response: response,
	}
}

func (h AlgorithmResponseHelper[T]) algorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmResponseHelper[T]) componentAlgorithmsResponseStatus(output dtos.CryptoOutput) (*common.StatusResponse, int) {
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

func (h AlgorithmResponseHelper[T]) WithStatus(ctx context.Context, s *zap.SugaredLogger, output interface{}) (response T) {
	statusResponse := &common.StatusResponse{
		Status:  common.StatusCode_FAILED,
		Message: ResponseMessageError,
	}
	httpCode := http.StatusInternalServerError
	cryptoOutput, ok := output.(dtos.CryptoOutput)
	if !ok {
		SetHTTPCodeOnTrailer(ctx, s, httpCode)
		return h.response
	}
	switch resp := any(h.response).(type) {
	case *pb.AlgorithmResponse:
		statusResponse, httpCode = h.algorithmsResponseStatus(cryptoOutput)
		resp.Status = statusResponse
	case *pb.ComponentsAlgorithmsResponse:
		statusResponse, httpCode = h.algorithmsResponseStatus(cryptoOutput)
		resp.Status = statusResponse
	case *pb.ComponentAlgorithmsResponse:
		statusResponse, httpCode = h.componentAlgorithmsResponseStatus(cryptoOutput)
		resp.Status = statusResponse
	}
	SetHTTPCodeOnTrailer(ctx, s, httpCode)
	return h.response
}
