// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package handlers

import (
	"context"
	"net/http"

	common "github.com/scanoss/papi/api/commonv2"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/httphelper"
)

// rejectIfInvalidComponents validates and converts ComponentsRequest with generic error handling.
//
// This generic function processes ComponentsRequest by converting it to ComponentDTO slice
// and handling validation errors. It uses Go generics to support any response type,
// making it reusable across all handler methods that accept multiple components.
//
// The function implements the guard clause pattern: if validation fails, it returns
// an empty DTO slice and an error response. If validation succeeds, it returns the
// converted DTOs and a zero value of type T (indicating no error response).
//
// Parameters:
//   - ctx: Context for setting HTTP status codes in gRPC trailers
//   - s: Structured logger for error logging
//   - request: ComponentsRequest containing multiple components to validate
//   - createResponse: Function to construct typed error response from StatusResponse
//
// Returns:
//   - []dtos.ComponentDTO: Slice of validated and converted components (empty if validation fails)
//   - T: Either zero value (success) or error response (failure) of generic type T
func rejectIfInvalidComponents[T any](ctx context.Context, s *zap.SugaredLogger, request *common.ComponentsRequest,
	createResponse func(*common.StatusResponse) T) ([]dtos.ComponentDTO, T) {
	componentDTOS, err := convertComponentsRequestToComponentDTO(request)
	if err != nil {
		s.Errorf("rejectIfInvalidComponents: %v, %v", request, err)
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusBadRequest)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return []dtos.ComponentDTO{}, createResponse(&statusResp)
	}
	var zero T
	return componentDTOS, zero
}

// rejectIfInvalid validates a single ComponentRequest with generic error handling.
//
// This generic function validates a ComponentRequest and implements the guard clause pattern.
// It uses Go generics to support any response type, making it reusable across all handler
// methods that accept a single component.
//
// If the request is valid, it returns the zero value of type T, which signals to the caller
// that processing can continue. If validation fails, it creates an error response using the
// provided createResponse function and sets HTTP 400 (Bad Request) in the gRPC trailer.
//
// Parameters:
//   - ctx: Context for setting HTTP status codes in gRPC trailers
//   - s: Structured logger for error logging
//   - request: ComponentRequest to validate
//   - createResponse: Function to construct typed error response from StatusResponse
//
// Returns:
//   - T: Either zero value (valid request) or error response (invalid request) of generic type T
func rejectIfInvalid[T any](ctx context.Context, s *zap.SugaredLogger, request *common.ComponentRequest, createResponse func(*common.StatusResponse) T) T {
	var zero T
	err := validateComponentRequest(request)
	if err != nil {
		s.Errorf("rejectIfInvalid: %v, %v", request, err)
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusBadRequest)
		statusResp := common.StatusResponse{Status: common.StatusCode_FAILED, Message: err.Error()}
		return createResponse(&statusResp)
	}
	return zero
}
