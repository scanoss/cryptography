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
	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/testutils"
)

func TestNewHintsInRangeHandler(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer models.CloseDB(db)

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	handler := NewHintsInRangeHandler(db, myConfig)
	if handler == nil {
		t.Error("NewHintsInRangeHandler() returned nil")
	}
	if handler.config == nil {
		t.Error("NewHintsInRangeHandler() handler.config is nil")
	}
}

func TestHintsRangeHandler_GetHintsInRange(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	tests := []struct {
		name          string
		request       *common.PurlRequest
		expectedPurls int
		expectedError bool
		status        common.StatusCode
	}{
		{
			name: "valid single purl request with range",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{
					{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: ">=0.0.0"},
				},
			},
			expectedPurls: 1,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "valid multiple purls request with range",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{
					{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: ">=0.0.0"},
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				},
			},
			expectedPurls: 2,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "empty purls array",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{},
			},
			expectedPurls: 0,
			expectedError: true,
			status:        common.StatusCode_FAILED,
		},
		{
			name: "purl not found in database",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{
					{Purl: "pkg:github/scanoss/nonexistent", Requirement: ">=1.0.0"},
				},
			},
			expectedPurls: 1,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "invalid purl format",
			request: &common.PurlRequest{
				Purls: []*common.PurlRequest_Purls{
					{Purl: "pkg:githubscanossengine", Requirement: ">=1.0.0"},
				},
			},
			expectedPurls: 1,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHintsInRangeHandler(db, myConfig)
			response, err := handler.GetHintsInRange(ctx, tt.request)

			if (err != nil) != tt.expectedError {
				t.Errorf("GetHintsInRange() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if response == nil {
				t.Error("GetHintsInRange() returned nil response")
				return
			}

			if len(response.Purls) != tt.expectedPurls {
				t.Errorf("GetHintsInRange() returned %d purls, expected %d", len(response.Purls), tt.expectedPurls)
			}

			if response.Status == nil {
				t.Error("GetHintsInRange() response.Status is nil")
				return
			}

			if response.Status.Status != tt.status {
				t.Errorf("GetHintsInRange() status = %v, expected %v", response.Status.Status, tt.status)
			}
		})
	}
}

func TestHintsRangeHandler_GetComponentsHintsInRange(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	tests := []struct {
		name               string
		request            *common.ComponentsRequest
		expectedComponents int
		expectedError      bool
		status             common.StatusCode
	}{
		{
			name: "valid single component request with range",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: ">=0.0.0"},
				},
			},
			expectedComponents: 1,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
		{
			name: "valid multiple components request with range",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: ">=0.0.0"},
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				},
			},
			expectedComponents: 2,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
		{
			name: "empty components array",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{},
			},
			expectedComponents: 0,
			expectedError:      false,
			status:             common.StatusCode_FAILED,
		},
		{
			name:               "nil request",
			request:            nil,
			expectedComponents: 0,
			expectedError:      false,
			status:             common.StatusCode_FAILED,
		},
		{
			name: "component not found in database",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/nonexistent", Requirement: ">=1.0.0"},
				},
			},
			expectedComponents: 1,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
		{
			name: "invalid purl format",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:githubscanossengine", Requirement: ">=1.0.0"},
				},
			},
			expectedComponents: 1,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
		{
			name: "empty purl",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "", Requirement: ">=1.0.0"},
				},
			},
			expectedComponents: 1,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
		{
			name: "wildcard requirement",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: "*"},
				},
			},
			expectedComponents: 1,
			expectedError:      false,
			status:             common.StatusCode_SUCCESS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHintsInRangeHandler(db, myConfig)
			response, err := handler.GetComponentsHintsInRange(ctx, tt.request)

			if (err != nil) != tt.expectedError {
				t.Errorf("GetComponentsHintsInRange() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if response == nil {
				t.Error("GetComponentsHintsInRange() returned nil response")
				return
			}

			if len(response.Components) != tt.expectedComponents {
				t.Errorf("GetComponentsHintsInRange() returned %d components, expected %d", len(response.Components), tt.expectedComponents)
			}

			if response.Status == nil {
				t.Error("GetComponentsHintsInRange() response.Status is nil")
				return
			}

			if response.Status.Status != tt.status {
				t.Errorf("GetComponentsHintsInRange() status = %v, expected %v", response.Status.Status, tt.status)
			}
		})
	}
}

func TestHintsRangeHandler_GetComponentHintsInRange(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database connection: %v", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	tests := []struct {
		name          string
		request       *common.ComponentRequest
		hasComponent  bool
		expectedError bool
		status        common.StatusCode
	}{
		{
			name: "valid component request with range",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/pineappleea/pineapple-src",
				Requirement: ">=0.0.0",
			},
			hasComponent:  true,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "component not found in database",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/scanoss/nonexistent",
				Requirement: ">=1.0.0",
			},
			hasComponent:  true,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "invalid purl format",
			request: &common.ComponentRequest{
				Purl:        "pkg:githubscanossengine",
				Requirement: ">=1.0.0",
			},
			hasComponent:  true,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "empty purl",
			request: &common.ComponentRequest{
				Purl:        "",
				Requirement: ">=1.0.0",
			},
			hasComponent:  false,
			expectedError: false,
			status:        common.StatusCode_FAILED,
		},
		{
			name: "missing requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/pineappleea/pineapple-src",
				Requirement: "",
			},
			hasComponent:  false,
			expectedError: false,
			status:        common.StatusCode_FAILED,
		},
		{
			name:          "nil request",
			request:       nil,
			hasComponent:  false,
			expectedError: false,
			status:        common.StatusCode_FAILED,
		},
		{
			name: "wildcard requirement",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/pineappleea/pineapple-src",
				Requirement: "*",
			},
			hasComponent:  true,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
		{
			name: "component without hints",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/scanoss/engine",
				Requirement: ">=1.0.0",
			},
			hasComponent:  true,
			expectedError: false,
			status:        common.StatusCode_SUCCESS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHintsInRangeHandler(db, myConfig)
			response, err := handler.GetComponentHintsInRange(ctx, tt.request)

			if (err != nil) != tt.expectedError {
				t.Errorf("GetComponentHintsInRange() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if response == nil {
				t.Error("GetComponentHintsInRange() returned nil response")
				return
			}

			if tt.hasComponent && response.Component == nil {
				t.Error("GetComponentHintsInRange() expected component but got nil")
			} else if !tt.hasComponent && response.Component != nil && len(response.Component.Hints) > 0 {
				t.Error("GetComponentHintsInRange() expected no component with hints but got one")
			}

			if response.Status == nil {
				t.Error("GetComponentHintsInRange() response.Status is nil")
				return
			}

			if response.Status.Status != tt.status {
				t.Errorf("GetComponentHintsInRange() status = %v, expected %v", response.Status.Status, tt.status)
			}
		})
	}
}
