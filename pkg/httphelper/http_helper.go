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
package httphelper

import (
	"context"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strconv"
)

// SetHTTPCodeOnTrailer sets the HTTP status code in the gRPC trailer metadata.
// This allows clients to determine the appropriate HTTP response code for the request.
func SetHTTPCodeOnTrailer(ctx context.Context, s *zap.SugaredLogger, code int) {
	err := grpc.SetTrailer(ctx, metadata.Pairs("x-http-code", strconv.Itoa(code)))
	if err != nil {
		s.Errorf("error setting x-http-code to trailer: %v\n", err)
	}
}
