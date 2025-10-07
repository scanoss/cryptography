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

// Package httpresponsehelper provides utilities for building standardized HTTP responses
// and status codes for gRPC services. It handles response status determination based on
// various error conditions and provides helpers for setting HTTP codes in gRPC trailers.
package httpresponsehelper

import (
	"context"
	common "github.com/scanoss/papi/api/commonv2"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net/http"
	"strconv"
)

const (
	// ResponseMessageSuccess is the default success message returned in responses.
	ResponseMessageSuccess = "Success"
	// ResponseMessageError is the default error message returned when an internal error occurs.
	ResponseMessageError = "Internal error occurred"
)

// Response is a generic interface for response builders that can attach status information.
// Implementations of this interface should populate the response with appropriate status
// codes and messages based on the operation outcome.
type Response[T any] interface {
	// WithStatus attaches status information to the response based on the output data.
	// Returns a response of type T with populated status fields.
	WithStatus(ctx context.Context, s *zap.SugaredLogger, output interface{}) T
}

// determineStatusForSingleAction evaluates error conditions for a single-item request
// and returns the appropriate status response and HTTP code.
//
// Parameters:
//   - malformed: count of malformed/invalid requests
//   - withOutInfo: count of requests with missing information
//   - notFound: count of requests where the resource was not found
//
// Returns a StatusResponse with the appropriate status code and message, along with
// the corresponding HTTP status code. Priority order: malformed > notFound > withOutInfo > success
func determineStatusForSingleAction(malformed int, withOutInfo int, notFound int) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK

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

// determineStatusForBatchAction evaluates error conditions for a batch/multi-item request
// and returns the appropriate status response and HTTP code.
//
// Parameters:
//   - malformed: count of malformed/invalid requests
//   - withOutInfo: count of requests with missing information
//   - notFound: count of requests where the resource was not found
//   - total: total number of items in the batch request
//
// Returns a StatusResponse with the appropriate status code and message, along with
// the corresponding HTTP status code. This function handles partial failures gracefully:
//   - Returns FAILED if all items are malformed
//   - Returns SUCCEEDED_WITH_WARNINGS if all items are not found or if there are partial errors
//   - Returns SUCCESS if all items were processed successfully
func determineStatusForBatchAction(malformed int, withOutInfo int, notFound int, total int) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK
	if malformed > 0 && malformed >= total {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusBadRequest
		response.Message = "Invalid purls"
		return &response, httpCode
	}

	if notFound > 0 && notFound >= total {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
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

// SetHTTPCodeOnTrailer sets the HTTP status code in the gRPC trailer metadata.
// This allows clients to determine the appropriate HTTP response code for the request.
func SetHTTPCodeOnTrailer(ctx context.Context, s *zap.SugaredLogger, code int) {
	err := grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", strconv.Itoa(code)))
	if err != nil {
		s.Errorf("error setting x-http-code to trailer: %v\n", err)
	}
}
