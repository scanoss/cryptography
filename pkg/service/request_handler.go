// Package service provides cryptography service handlers and utilities for gRPC requests.
package service

import (
	"context"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/protocol/rest"

	common "github.com/scanoss/papi/api/commonv2"
	"scanoss.com/cryptography/pkg/dtos"
)

// rejectIfInvalidComponents processes multiple components requests with generic response handling.
// It converts the request to ComponentDTO format and handles errors appropriately.
// Returns the converted DTOs, the response (if error occurred), and any error.
func rejectIfInvalidComponents[T any](ctx context.Context, s *zap.SugaredLogger, request *common.ComponentsRequest, createResponse func(*common.StatusResponse) T) ([]dtos.ComponentDTO, T) {
	componentDTOS, err := convertComponentsRequestToComponentDTO(request)
	if err != nil {
		s.Errorf("rejectIfInvalidComponents: %v, %v", request, err)
		setHTTPCodeOnTrailer(ctx, s, rest.HTTPStatusBadRequest)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return []dtos.ComponentDTO{}, createResponse(&statusResp)
	}
	var zero T
	return componentDTOS, zero
}

// rejectIfInvalid validates a single component request and acts as a gatekeeper.
// If the request is valid, it returns the zero value of type T (allowing processing to continue).
// If validation fails, it creates an error response using the provided createResponse function
// and sets the appropriate HTTP status code in the context trailer.
// This function serves as a guard clause pattern for component request validation.
func rejectIfInvalid[T any](ctx context.Context, s *zap.SugaredLogger, request *common.ComponentRequest, createResponse func(*common.StatusResponse) T) T {
	var zero T
	err := validateComponentRequest(request)
	if err != nil {
		s.Errorf("rejectIfInvalid: %v, %v", request, err)
		setHTTPCodeOnTrailer(ctx, s, rest.HTTPStatusBadRequest)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return createResponse(&statusResp)
	}
	return zero
}
