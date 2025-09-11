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

package service

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	common "github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/dtos"
)

type mockStatusResponse struct {
	status  common.StatusCode
	message string
}

func Test_handleComponentsRequest(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	createResponseFunc := func(statusResp *common.StatusResponse) *mockStatusResponse {
		return &mockStatusResponse{
			status:  statusResp.Status,
			message: statusResp.Message,
		}
	}

	tests := []struct {
		name           string
		request        *common.ComponentsRequest
		wantComponents []dtos.ComponentDTO
		wantResponse   *mockStatusResponse
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name: "valid components request",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{
						Purl:        "pkg:npm/lodash",
						Requirement: "^4.17.0",
					},
				},
			},
			wantComponents: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/lodash",
					Version:     "^4.17.0",
					Requirement: "^4.17.0",
				},
			},
			wantResponse: nil,
			wantErr:      false,
		},
		{
			name:           "nil request",
			request:        nil,
			wantComponents: []dtos.ComponentDTO{},
			wantResponse:   &mockStatusResponse{status: common.StatusCode_FAILED, message: "'components' field is required but was not provided"},
			wantErr:        true,
			expectedErrMsg: "'components' field is required but was not provided",
		},
		{
			name: "request with nil components",
			request: &common.ComponentsRequest{
				Components: nil,
			},
			wantComponents: []dtos.ComponentDTO{},
			wantResponse:   &mockStatusResponse{status: common.StatusCode_FAILED, message: "'components' field is required but was not provided"},
			wantErr:        true,
			expectedErrMsg: "'components' field is required but was not provided",
		},
		{
			name: "request with empty components",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{},
			},
			wantComponents: []dtos.ComponentDTO{},
			wantResponse:   &mockStatusResponse{status: common.StatusCode_FAILED, message: "'components' array cannot be empty, at least one component must be provided"},
			wantErr:        true,
			expectedErrMsg: "'components' array cannot be empty, at least one component must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotComponents, gotResponse, err := handleComponentsRequest(ctx, tt.request, createResponseFunc)

			if tt.wantErr {
				if err == nil {
					t.Errorf("handleComponentsRequest() expected error but got nil")
					return
				}
				if err.Error() != tt.expectedErrMsg {
					t.Errorf("handleComponentsRequest() error = %v, want %v", err.Error(), tt.expectedErrMsg)
				}
				if gotResponse == nil {
					t.Errorf("handleComponentsRequest() expected response but got nil")
					return
				}
				if gotResponse.status != tt.wantResponse.status {
					t.Errorf("handleComponentsRequest() response status = %v, want %v", gotResponse.status, tt.wantResponse.status)
				}
				if gotResponse.message != tt.wantResponse.message {
					t.Errorf("handleComponentsRequest() response message = %v, want %v", gotResponse.message, tt.wantResponse.message)
				}
			} else {
				if err != nil {
					t.Errorf("handleComponentsRequest() unexpected error = %v", err)
					return
				}
				if gotResponse != nil {
					t.Errorf("handleComponentsRequest() expected nil response but got %v", gotResponse)
				}
			}

			if len(gotComponents) != len(tt.wantComponents) {
				t.Errorf("handleComponentsRequest() components length = %v, want %v", len(gotComponents), len(tt.wantComponents))
				return
			}

			for i, component := range gotComponents {
				if component.Purl != tt.wantComponents[i].Purl {
					t.Errorf("handleComponentsRequest() component[%d].Purl = %v, want %v", i, component.Purl, tt.wantComponents[i].Purl)
				}
				if component.Version != tt.wantComponents[i].Version {
					t.Errorf("handleComponentsRequest() component[%d].Version = %v, want %v", i, component.Version, tt.wantComponents[i].Version)
				}
				if component.Requirement != tt.wantComponents[i].Requirement {
					t.Errorf("handleComponentsRequest() component[%d].Requirement = %v, want %v", i, component.Requirement, tt.wantComponents[i].Requirement)
				}
			}
		})
	}
}

func Test_handleComponentRequest(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)

	createResponseFunc := func(statusResp *common.StatusResponse) *mockStatusResponse {
		return &mockStatusResponse{
			status:  statusResp.Status,
			message: statusResp.Message,
		}
	}

	tests := []struct {
		name           string
		request        *common.ComponentRequest
		wantComponents []dtos.ComponentDTO
		wantResponse   *mockStatusResponse
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name: "valid component request",
			request: &common.ComponentRequest{
				Purl:        "pkg:npm/react",
				Requirement: "^17.0.0",
			},
			wantComponents: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/react",
					Version:     "^17.0.0",
					Requirement: "^17.0.0",
				},
			},
			wantResponse: nil,
			wantErr:      false,
		},
		{
			name:           "nil request",
			request:        nil,
			wantComponents: []dtos.ComponentDTO{},
			wantResponse:   &mockStatusResponse{status: common.StatusCode_FAILED, message: "no purl supplied. A PURL is required"},
			wantErr:        true,
			expectedErrMsg: "no purl supplied. A PURL is required",
		},
		{
			name: "empty purl component request",
			request: &common.ComponentRequest{
				Purl:        "",
				Requirement: "^17.0.0",
			},
			wantComponents: []dtos.ComponentDTO{},
			wantResponse:   &mockStatusResponse{status: common.StatusCode_FAILED, message: "no purl supplied. A PURL is required"},
			wantErr:        true,
			expectedErrMsg: "no purl supplied. A PURL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotComponents, gotResponse, err := handleComponentRequest(ctx, tt.request, createResponseFunc)

			if tt.wantErr {
				if err == nil {
					t.Errorf("handleComponentRequest() expected error but got nil")
					return
				}
				if err.Error() != tt.expectedErrMsg {
					t.Errorf("handleComponentRequest() error = %v, want %v", err.Error(), tt.expectedErrMsg)
				}
				if gotResponse == nil {
					t.Errorf("handleComponentRequest() expected response but got nil")
					return
				}
				if gotResponse.status != tt.wantResponse.status {
					t.Errorf("handleComponentRequest() response status = %v, want %v", gotResponse.status, tt.wantResponse.status)
				}
				if gotResponse.message != tt.wantResponse.message {
					t.Errorf("handleComponentRequest() response message = %v, want %v", gotResponse.message, tt.wantResponse.message)
				}
			} else {
				if err != nil {
					t.Errorf("handleComponentRequest() unexpected error = %v", err)
					return
				}
				if gotResponse != nil {
					t.Errorf("handleComponentRequest() expected nil response but got %v", gotResponse)
				}
			}

			if len(gotComponents) != len(tt.wantComponents) {
				t.Errorf("handleComponentRequest() components length = %v, want %v", len(gotComponents), len(tt.wantComponents))
				return
			}

			for i, component := range gotComponents {
				if component.Purl != tt.wantComponents[i].Purl {
					t.Errorf("handleComponentRequest() component[%d].Purl = %v, want %v", i, component.Purl, tt.wantComponents[i].Purl)
				}
				if component.Version != tt.wantComponents[i].Version {
					t.Errorf("handleComponentRequest() component[%d].Version = %v, want %v", i, component.Version, tt.wantComponents[i].Version)
				}
				if component.Requirement != tt.wantComponents[i].Requirement {
					t.Errorf("handleComponentRequest() component[%d].Requirement = %v, want %v", i, component.Requirement, tt.wantComponents[i].Requirement)
				}
			}
		})
	}
}
