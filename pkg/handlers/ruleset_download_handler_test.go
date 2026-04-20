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
	"path/filepath"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	myconfig "scanoss.com/cryptography/pkg/config"
)

func TestNewRulesetDownloadHandler(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = "/tmp/rulesets"

	handler := NewRulesetDownloadHandler(config)
	if handler == nil {
		t.Error("NewRulesetDownloadHandler() returned nil")
	}
	if handler.config == nil {
		t.Error("NewRulesetDownloadHandler() config is nil")
	}
	if handler.rulesetDownloadUseCase == nil {
		t.Error("NewRulesetDownloadHandler() rulesetDownloadUseCase is nil")
	}
}

func TestRulesetDownloadHandler_validateRequest(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = "/tmp/rulesets"

	handler := NewRulesetDownloadHandler(config)

	tests := []struct {
		name          string
		request       *pb.RulesetDownloadRequest
		expectError   bool
		errorContains string
	}{
		{
			name: "valid request with specific version",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "v1.0.0",
			},
			expectError: false,
		},
		{
			name: "valid request with latest",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "latest",
			},
			expectError: false,
		},
		{
			name:          "nil request",
			request:       nil,
			expectError:   true,
			errorContains: "cannot be empty",
		},
		{
			name: "empty ruleset name",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "",
				Version:     "v1.0.0",
			},
			expectError:   true,
			errorContains: "ruleset_name cannot be empty",
		},
		{
			name: "empty version",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "",
			},
			expectError:   true,
			errorContains: "version cannot be empty",
		},
		{
			name: "whitespace only ruleset name",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "   ",
				Version:     "v1.0.0",
			},
			expectError:   true,
			errorContains: "ruleset_name cannot be empty",
		},
		{
			name: "whitespace only version",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "   ",
			},
			expectError:   true,
			errorContains: "version cannot be empty",
		},
		{
			name: "invalid semver version",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "not-a-version",
			},
			expectError:   true,
			errorContains: "valid semver",
		},
		{
			name: "valid semver without v prefix",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "1.0.0",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateRequest(tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorContains)
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestRulesetDownloadHandler_DownloadRuleset(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	// Get the project root directory
	projectRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get project root: %v", err)
	}
	testStoragePath := filepath.Join(projectRoot, "test-support", "rulesets")

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = testStoragePath

	handler := NewRulesetDownloadHandler(config)
	ctx := context.Background()
	ctx = ctxzap.ToContext(ctx, zlog.L)

	tests := []struct {
		name           string
		request        *pb.RulesetDownloadRequest
		expectError    bool
		expectedCode   codes.Code
		errorContains  string
		validateResult func(t *testing.T, contentType string, dataLen int)
	}{
		{
			name: "invalid request - empty ruleset name",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "",
				Version:     "v1.0.0",
			},
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "invalid request",
		},
		{
			name: "invalid request - empty version",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "",
			},
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "invalid request",
		},
		{
			name: "ruleset not found",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "nonexistent-ruleset",
				Version:     "v1.0.0",
			},
			expectError:   true,
			expectedCode:  codes.NotFound,
			errorContains: "not found",
		},
		{
			name: "version not found",
			request: &pb.RulesetDownloadRequest{
				RulesetName: "dca",
				Version:     "v99.99.99",
			},
			expectError:   true,
			expectedCode:  codes.NotFound,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.DownloadRuleset(ctx, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}

				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("Expected gRPC status error, got: %v", err)
					return
				}

				if st.Code() != tt.expectedCode {
					t.Errorf("Expected code %v, got %v", tt.expectedCode, st.Code())
				}

				if tt.errorContains != "" && !strings.Contains(st.Message(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, st.Message())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
					return
				}

				if result == nil {
					t.Error("Expected non-nil result")
					return
				}

				if tt.validateResult != nil {
					tt.validateResult(t, result.ContentType, len(result.Data))
				}
			}
		})
	}
}

func TestRulesetDownloadHandler_handleUseCaseError(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = "/tmp/rulesets"

	handler := NewRulesetDownloadHandler(config)
	ctx := context.Background()
	ctx = ctxzap.ToContext(ctx, zlog.L)
	s := zlog.S

	tests := []struct {
		name         string
		inputError   error
		expectedCode codes.Code
		errorPattern string
	}{
		{
			name:         "not found error",
			inputError:   &customError{msg: "ruleset not found"},
			expectedCode: codes.NotFound,
			errorPattern: "requested ruleset or version not found",
		},
		{
			name:         "does not exist error",
			inputError:   &customError{msg: "file does not exist"},
			expectedCode: codes.NotFound,
			errorPattern: "requested ruleset or version not found",
		},
		{
			name:         "failed to resolve error",
			inputError:   &customError{msg: "failed to resolve version"},
			expectedCode: codes.Internal,
			errorPattern: "internal server error",
		},
		{
			name:         "failed to read error",
			inputError:   &customError{msg: "failed to read metadata"},
			expectedCode: codes.Internal,
			errorPattern: "internal server error",
		},
		{
			name:         "failed to parse error",
			inputError:   &customError{msg: "failed to parse manifest"},
			expectedCode: codes.Internal,
			errorPattern: "internal server error",
		},
		{
			name:         "integrity check failed error",
			inputError:   &customError{msg: "tarball integrity check failed"},
			expectedCode: codes.DataLoss,
			errorPattern: "ruleset integrity verification failed",
		},
		{
			name:         "checksum error",
			inputError:   &customError{msg: "checksum mismatch"},
			expectedCode: codes.DataLoss,
			errorPattern: "ruleset integrity verification failed",
		},
		{
			name:         "unexpected error",
			inputError:   &customError{msg: "some random error"},
			expectedCode: codes.Internal,
			errorPattern: "internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.handleUseCaseError(ctx, s, tt.inputError)

			if err == nil {
				t.Error("Expected error, got nil")
				return
			}

			if result != nil {
				t.Errorf("Expected nil result, got: %v", result)
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Errorf("Expected gRPC status error, got: %v", err)
				return
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("Expected code %v, got %v", tt.expectedCode, st.Code())
			}

			if !strings.Contains(st.Message(), tt.errorPattern) {
				t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorPattern, st.Message())
			}
		})
	}
}

// customError is a helper type for testing error handling.
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}
