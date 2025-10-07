package httpresponsehelper

import (
	"context"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type EncryptionHintsResponseHelper[T any] struct {
	response T
}

func NewEncryptionHintsResponseHelper[T any](response T) Response[T] {
	return &EncryptionHintsResponseHelper[T]{
		response: response,
	}
}

func (h EncryptionHintsResponseHelper[T]) componentsEncryptionHintsResponseStatus(output dtos.HintsOutput) (*common.StatusResponse, int) {
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

func (h EncryptionHintsResponseHelper[T]) componentEncryptionHintsResponseStatus(output dtos.HintsOutput) (*common.StatusResponse, int) {
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

func (h EncryptionHintsResponseHelper[T]) WithStatus(ctx context.Context, s *zap.SugaredLogger, output interface{}) (response T) {
	statusResponse := &common.StatusResponse{
		Status:  common.StatusCode_FAILED,
		Message: ResponseMessageError,
	}
	httpCode := http.StatusInternalServerError
	hintsOutput, ok := output.(dtos.HintsOutput)
	if !ok {
		SetHTTPCodeOnTrailer(ctx, s, httpCode)
		return h.response
	}
	switch resp := any(h.response).(type) {
	case *pb.HintsResponse:
		statusResponse, httpCode = h.componentsEncryptionHintsResponseStatus(hintsOutput)
		resp.Status = statusResponse
	case *pb.ComponentsEncryptionHintsResponse:
		statusResponse, httpCode = h.componentsEncryptionHintsResponseStatus(hintsOutput)
		resp.Status = statusResponse
	case *pb.ComponentEncryptionHintsResponse:
		statusResponse, httpCode = h.componentEncryptionHintsResponseStatus(hintsOutput)
		resp.Status = statusResponse
	}
	SetHTTPCodeOnTrailer(ctx, s, httpCode)
	return h.response
}
