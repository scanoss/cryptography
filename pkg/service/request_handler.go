// Package service provides cryptography service handlers and utilities for gRPC requests.
package service

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	common "github.com/scanoss/papi/api/commonv2"
	"scanoss.com/cryptography/pkg/dtos"
)

// handleComponentsRequest processes multiple components requests with generic response handling.
// It converts the request to ComponentDTO format and handles errors appropriately.
// Returns the converted DTOs, the response (if error occurred), and any error.
func handleComponentsRequest[T any](ctx context.Context, request *common.ComponentsRequest, createResponse func(*common.StatusResponse) T) ([]dtos.ComponentDTO, T, error) {
	s := ctxzap.Extract(ctx).Sugar()
	var zero T
	componentDTOS, err := convertComponentsRequestToComponentDTO(request)
	if err != nil {
		setHTTPCodeOnTrailer(ctx, s, "400")
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return []dtos.ComponentDTO{}, createResponse(&statusResp), errors.New(err.Error())
	}
	return componentDTOS, zero, nil
}

// handleComponentRequest processes a single component request with generic response handling.
// It converts the request to ComponentDTO format and handles errors appropriately.
// Returns the converted DTOs as a slice, the response (if error occurred), and any error.
func handleComponentRequest[T any](ctx context.Context, request *common.ComponentRequest, createResponse func(*common.StatusResponse) T) ([]dtos.ComponentDTO, T, error) {
	s := ctxzap.Extract(ctx).Sugar()
	var zero T
	componentDTOS, err := convertComponentRequestToComponentDTO(request)
	if err != nil {
		setHTTPCodeOnTrailer(ctx, s, "400")
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return []dtos.ComponentDTO{}, createResponse(&statusResp), errors.New(err.Error())
	}
	return []dtos.ComponentDTO{componentDTOS}, zero, nil
}
