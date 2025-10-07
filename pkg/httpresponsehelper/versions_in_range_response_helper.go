package httpresponsehelper

import (
	"context"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"net/http"
	"scanoss.com/cryptography/pkg/dtos"
)

type VersionsInRangeResponseHelper[T any] struct {
	response T
}

// Constructor that returns the interface type
func NewVersionsInRangeResponseHelper[T any](response T) Response[T] {
	return &VersionsInRangeResponseHelper[T]{
		response: response,
	}
}

func (h VersionsInRangeResponseHelper[T]) versionsInRangeResponseStatus(output dtos.VersionsInRangeOutput) (*common.StatusResponse, int) {
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

func (h VersionsInRangeResponseHelper[T]) componentVersionsInRangeResponseStatus(output dtos.VersionsInRangeOutput) (*common.StatusResponse, int) {
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

func (h VersionsInRangeResponseHelper[T]) WithStatus(ctx context.Context, s *zap.SugaredLogger, output interface{}) (response T) {
	statusResponse := &common.StatusResponse{
		Status:  common.StatusCode_FAILED,
		Message: ResponseMessageError,
	}
	httpCode := http.StatusInternalServerError
	versionsInRangeOutput, ok := output.(dtos.VersionsInRangeOutput)
	if !ok {
		SetHTTPCodeOnTrailer(ctx, s, httpCode)
		return h.response
	}
	switch resp := any(h.response).(type) {
	case *pb.VersionsInRangeResponse:
		statusResponse, httpCode = h.versionsInRangeResponseStatus(versionsInRangeOutput)
		resp.Status = statusResponse
	case *pb.ComponentsVersionsInRangeResponse:
		statusResponse, httpCode = h.versionsInRangeResponseStatus(versionsInRangeOutput)
		resp.Status = statusResponse
	case *pb.ComponentVersionsInRangeResponse:
		statusResponse, httpCode = h.componentVersionsInRangeResponseStatus(versionsInRangeOutput)
		resp.Status = statusResponse
	}
	SetHTTPCodeOnTrailer(ctx, s, httpCode)
	return h.response
}
