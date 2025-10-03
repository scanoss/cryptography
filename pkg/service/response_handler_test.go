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
	common "github.com/scanoss/papi/api/commonv2"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
	"scanoss.com/cryptography/pkg/handler"
	"scanoss.com/cryptography/pkg/models"
	"testing"
)

func Test_buildErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		summary models.QuerySummary
		want    []string
	}{
		{
			name: "no errors",
			summary: models.QuerySummary{
				TotalPurls:         3,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			want: []string{},
		},
		{
			name: "failed to parse only",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{"invalid-purl1", "invalid-purl2"},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			want: []string{"Failed to parse 2 purl(s):invalid-purl1,invalid-purl2"},
		},
		{
			name: "not found only",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{"pkg:npm/missing@1.0.0", "pkg:npm/missing2@2.0.0"},
				PurlsWOInfo:        []string{},
			},
			want: []string{"Can't find 2 purl(s):pkg:npm/missing@1.0.0,pkg:npm/missing2@2.0.0"},
		},
		{
			name: "no info only",
			summary: models.QuerySummary{
				TotalPurls:         1,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{"pkg:npm/noinfo@1.0.0"},
			},
			want: []string{"Can't find information for 1 purl(s):pkg:npm/noinfo@1.0.0"},
		},
		{
			name: "all error types",
			summary: models.QuerySummary{
				TotalPurls:         5,
				PurlsFailedToParse: []string{"invalid-purl"},
				PurlsNotFound:      []string{"pkg:npm/missing@1.0.0"},
				PurlsWOInfo:        []string{"pkg:npm/noinfo@1.0.0"},
			},
			want: []string{
				"Failed to parse 1 purl(s):invalid-purl",
				"Can't find 1 purl(s):pkg:npm/missing@1.0.0",
				"Can't find information for 1 purl(s):pkg:npm/noinfo@1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handler.buildErrorMessages(tt.summary)

			if len(got) != len(tt.want) {
				t.Errorf("buildErrorMessages() length = %d, want %d", len(got), len(tt.want))
				return
			}

			for i, message := range got {
				if message != tt.want[i] {
					t.Errorf("buildErrorMessages()[%d] = %v, want %v", i, message, tt.want[i])
				}
			}
		})
	}
}

func Test_determineStatusAndHTTPCode(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	tests := []struct {
		name         string
		summary      models.QuerySummary
		wantStatus   common.StatusCode
		wantHTTPCode string
	}{
		{
			name: "all successful",
			summary: models.QuerySummary{
				TotalPurls:         3,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			wantStatus:   common.StatusCode_SUCCESS,
			wantHTTPCode: "200",
		},
		{
			name: "all failed to parse",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{"invalid-purl1", "invalid-purl2"},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			wantStatus:   common.StatusCode_FAILED,
			wantHTTPCode: "400",
		},
		{
			name: "all not found",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{"pkg:npm/missing@1.0.0", "pkg:npm/missing2@2.0.0"},
				PurlsWOInfo:        []string{},
			},
			wantStatus:   common.StatusCode_FAILED,
			wantHTTPCode: "404",
		},
		{
			name: "all no info",
			summary: models.QuerySummary{
				TotalPurls:         1,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{"pkg:npm/noinfo@1.0.0"},
			},
			wantStatus:   common.StatusCode_FAILED,
			wantHTTPCode: "404",
		},
		{
			name: "mixed results - some successful",
			summary: models.QuerySummary{
				TotalPurls:         4,
				PurlsFailedToParse: []string{"invalid-purl"},
				PurlsNotFound:      []string{"pkg:npm/missing@1.0.0"},
				PurlsWOInfo:        []string{},
			},
			wantStatus:   common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			wantHTTPCode: "200",
		},
		{
			name: "mixed failures with parse errors taking priority",
			summary: models.QuerySummary{
				TotalPurls:         3,
				PurlsFailedToParse: []string{"invalid1", "invalid2", "invalid3"},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			wantStatus:   common.StatusCode_FAILED,
			wantHTTPCode: "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotHTTPCode := handler.determineStatusAndHTTPCode(sugar, tt.summary)

			if gotStatus != tt.wantStatus {
				t.Errorf("determineStatusAndHTTPCode() status = %v, want %v", gotStatus, tt.wantStatus)
			}
			if gotHTTPCode != tt.wantHTTPCode {
				t.Errorf("determineStatusAndHTTPCode() httpCode = %v, want %v", gotHTTPCode, tt.wantHTTPCode)
			}
		})
	}
}

func Test_buildStatusResponse(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	tests := []struct {
		name        string
		summary     models.QuerySummary
		wantStatus  common.StatusCode
		wantMessage string
	}{
		{
			name: "successful response",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			wantStatus:  common.StatusCode_SUCCESS,
			wantMessage: handler.ResponseMessageSuccess,
		},
		{
			name: "response with single error",
			summary: models.QuerySummary{
				TotalPurls:         2,
				PurlsFailedToParse: []string{"invalid-purl"},
				PurlsNotFound:      []string{},
				PurlsWOInfo:        []string{},
			},
			wantStatus:  common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			wantMessage: "Failed to parse 1 purl(s):invalid-purl",
		},
		{
			name: "response with multiple error types",
			summary: models.QuerySummary{
				TotalPurls:         5,
				PurlsFailedToParse: []string{"invalid-purl"},
				PurlsNotFound:      []string{"pkg:npm/missing@1.0.0"},
				PurlsWOInfo:        []string{"pkg:npm/noinfo@1.0.0"},
			},
			wantStatus:  common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			wantMessage: "Failed to parse 1 purl(s):invalid-purl | Can't find 1 purl(s):pkg:npm/missing@1.0.0 | Can't find information for 1 purl(s):pkg:npm/noinfo@1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got := buildStatusResponse(ctx, sugar, tt.summary)

			if got.Status != tt.wantStatus {
				t.Errorf("buildStatusResponse() status = %v, want %v", got.Status, tt.wantStatus)
			}
			if got.Message != tt.wantMessage {
				t.Errorf("buildStatusResponse() message = %v, want %v", got.Message, tt.wantMessage)
			}
		})
	}
}

func Test_setHTTPCodeOnTrailer(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	tests := []struct {
		name string
		code string
	}{
		{
			name: "set 200 code",
			code: "200",
		},
		{
			name: "set 400 code",
			code: "400",
		},
		{
			name: "set 404 code",
			code: "404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Mock the grpc.SetTrailer function by creating a context with metadata
			md := metadata.New(map[string]string{})
			ctx = metadata.NewOutgoingContext(ctx, md)

			// This test mainly ensures the function doesn't panic
			// and handles the trailer setting gracefully
			handler.setHTTPCodeOnTrailer(ctx, sugar, tt.code)
		})
	}
}
