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
