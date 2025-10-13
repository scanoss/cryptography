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
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	common "github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/dtos"
)

func Test_buildComponentDTO(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		requirement string
		want        dtos.ComponentDTO
	}{
		{
			name:        "purl without version and no requirement",
			purl:        "pkg:npm/lodash",
			requirement: "",
			want: dtos.ComponentDTO{
				Purl:        "pkg:npm/lodash",
				Version:     "",
				Requirement: "",
			},
		},
		{
			name:        "purl without version with requirement",
			purl:        "pkg:npm/lodash",
			requirement: "^4.17.0",
			want: dtos.ComponentDTO{
				Purl:        "pkg:npm/lodash",
				Version:     "^4.17.0",
				Requirement: "^4.17.0",
			},
		},
		{
			name:        "purl with version overrides empty requirement",
			purl:        "pkg:npm/react@17.0.2",
			requirement: "",
			want: dtos.ComponentDTO{
				Purl:        "pkg:npm/react",
				Version:     "17.0.2",
				Requirement: "17.0.2",
			},
		},
		{
			name:        "purl with version overrides provided requirement",
			purl:        "pkg:npm/react@17.0.2",
			requirement: "^17.0.0",
			want: dtos.ComponentDTO{
				Purl:        "pkg:npm/react",
				Version:     "17.0.2",
				Requirement: "17.0.2",
			},
		},
		{
			name:        "purl with complex version",
			purl:        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4",
			requirement: "",
			want: dtos.ComponentDTO{
				Purl:        "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
				Version:     "2.13.4",
				Requirement: "2.13.4",
			},
		},
		{
			name:        "purl with range requirement",
			purl:        "pkg:pypi/django",
			requirement: ">=3.2.0,<4.0.0",
			want: dtos.ComponentDTO{
				Purl:        "pkg:pypi/django",
				Version:     ">=3.2.0,<4.0.0",
				Requirement: ">=3.2.0,<4.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildComponentDTO(tt.purl, tt.requirement)
			if got.Purl != tt.want.Purl {
				t.Errorf("buildComponentDTO() Purl = %v, want %v", got.Purl, tt.want.Purl)
			}
			if got.Version != tt.want.Version {
				t.Errorf("buildComponentDTO() Version = %v, want %v", got.Version, tt.want.Version)
			}
			if got.Requirement != tt.want.Requirement {
				t.Errorf("buildComponentDTO() Requirement = %v, want %v", got.Requirement, tt.want.Requirement)
			}
		})
	}
}

func Test_ConvertPurlRequestToComponentDTO(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()

	tests := []struct {
		name        string
		request     *common.PurlRequest
		want        []dtos.ComponentDTO
		expectError bool
	}{
		{
			name: "valid single purl request",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{{Purl: "pkg:npm/lodash@4.17.21"}},
			},
			want: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/lodash",
					Version:     "4.17.21",
					Requirement: "4.17.21",
				},
			},
			expectError: false,
		},
		{
			name: "valid multiple purls request",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{
					{Purl: "pkg:npm/react@17.0.2"},
					{Purl: "pkg:npm/lodash@4.17.21"},
				},
			},
			want: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/react",
					Version:     "17.0.2",
					Requirement: "17.0.2",
				},
				{
					Purl:        "pkg:npm/lodash",
					Version:     "4.17.21",
					Requirement: "4.17.21",
				},
			},
			expectError: false,
		},
		{
			name: "empty purls array",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{},
			},
			want:        []dtos.ComponentDTO{},
			expectError: true,
		},
		{
			name:        "nil request",
			request:     nil,
			want:        []dtos.ComponentDTO{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertPurlRequestToComponentDTO(s, tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("ConvertPurlRequestToComponentDTO() expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ConvertPurlRequestToComponentDTO() unexpected error = %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ConvertPurlRequestToComponentDTO() length = %v, want %v", len(got), len(tt.want))
				return
			}

			for i, component := range got {
				if component.Purl != tt.want[i].Purl {
					t.Errorf("ConvertPurlRequestToComponentDTO() component[%d].Purl = %v, want %v", i, component.Purl, tt.want[i].Purl)
				}
				if component.Version != tt.want[i].Version {
					t.Errorf("ConvertPurlRequestToComponentDTO() component[%d].Version = %v, want %v", i, component.Version, tt.want[i].Version)
				}
				if component.Requirement != tt.want[i].Requirement {
					t.Errorf("ConvertPurlRequestToComponentDTO() component[%d].Requirement = %v, want %v", i, component.Requirement, tt.want[i].Requirement)
				}
			}
		})
	}
}

func Test_convertComponentsRequestToComponentDTO(t *testing.T) {
	tests := []struct {
		name        string
		request     *common.ComponentsRequest
		want        []dtos.ComponentDTO
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid single component request",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{
						Purl:        "pkg:npm/lodash",
						Requirement: "^4.17.0",
					},
				},
			},
			want: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/lodash",
					Version:     "^4.17.0",
					Requirement: "^4.17.0",
				},
			},
			expectError: false,
		},
		{
			name: "valid multiple components request",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{
						Purl:        "pkg:npm/react",
						Requirement: "^17.0.0",
					},
					{
						Purl:        "pkg:npm/lodash@4.17.21",
						Requirement: "",
					},
				},
			},
			want: []dtos.ComponentDTO{
				{
					Purl:        "pkg:npm/react",
					Version:     "^17.0.0",
					Requirement: "^17.0.0",
				},
				{
					Purl:        "pkg:npm/lodash",
					Version:     "4.17.21",
					Requirement: "4.17.21",
				},
			},
			expectError: false,
		},
		{
			name:        "nil request",
			request:     nil,
			want:        nil,
			expectError: true,
			errorMsg:    "'components' field is required but was not provided",
		},
		{
			name: "request with nil components",
			request: &common.ComponentsRequest{
				Components: nil,
			},
			want:        nil,
			expectError: true,
			errorMsg:    "'components' field is required but was not provided",
		},
		{
			name: "request with empty components array",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{},
			},
			want:        nil,
			expectError: true,
			errorMsg:    "'components' array cannot be empty, at least one component must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertComponentsRequestToComponentDTO(tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("convertComponentsRequestToComponentDTO() expected error but got nil")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("convertComponentsRequestToComponentDTO() error = %v, want %v", err.Error(), tt.errorMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("convertComponentsRequestToComponentDTO() unexpected error = %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("convertComponentsRequestToComponentDTO() length = %v, want %v", len(got), len(tt.want))
				return
			}

			for i, component := range got {
				if component.Purl != tt.want[i].Purl {
					t.Errorf("convertComponentsRequestToComponentDTO() component[%d].Purl = %v, want %v", i, component.Purl, tt.want[i].Purl)
				}
				if component.Version != tt.want[i].Version {
					t.Errorf("convertComponentsRequestToComponentDTO() component[%d].Version = %v, want %v", i, component.Version, tt.want[i].Version)
				}
				if component.Requirement != tt.want[i].Requirement {
					t.Errorf("convertComponentsRequestToComponentDTO() component[%d].Requirement = %v, want %v", i, component.Requirement, tt.want[i].Requirement)
				}
			}
		})
	}
}

func Test_validateComponentRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *common.ComponentRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid component request with purl and requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:npm/react",
				Requirement: "^17.0.0",
			},
			expectError: false,
		},
		{
			name: "valid component request with only purl",
			request: &common.ComponentRequest{
				Purl: "pkg:npm/react",
			},
			expectError: false,
		},
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "no purl supplied. A PURL is required",
		},
		{
			name: "empty purl",
			request: &common.ComponentRequest{
				Purl:        "",
				Requirement: "^17.0.0",
			},
			expectError: true,
			errorMsg:    "no purl supplied. A PURL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateComponentRequest(tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("validateComponentRequest() expected error but got nil")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("validateComponentRequest() error = %v, want %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateComponentRequest() unexpected error = %v", err)
				}
			}
		})
	}
}

func Test_validateComponentRequestRange(t *testing.T) {
	tests := []struct {
		name        string
		request     *common.ComponentRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid component request with purl and requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:npm/react",
				Requirement: "^17.0.0",
			},
			expectError: false,
		},
		{
			name: "valid component request with range requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:pypi/django",
				Requirement: ">=3.2.0,<4.0.0",
			},
			expectError: false,
		},
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "no purl supplied. A PURL is required",
		},
		{
			name: "empty purl",
			request: &common.ComponentRequest{
				Purl:        "",
				Requirement: "^17.0.0",
			},
			expectError: true,
			errorMsg:    "no purl supplied. A PURL is required",
		},
		{
			name: "missing requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:npm/react",
				Requirement: "",
			},
			expectError: true,
			errorMsg:    "no requirement supplied. A requirement is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateComponentRequestRange(tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("validateComponentRequestRange() expected error but got nil")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("validateComponentRequestRange() error = %v, want %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateComponentRequestRange() unexpected error = %v", err)
				}
			}
		})
	}
}