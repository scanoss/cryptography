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

package usecase

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

func TestLibrariesDetectionUseCase_InRange(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseConn(conn)
	err = models.LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	var componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/pineappleea/pineapple-src",
			Requirement: ">=0",
		},
	}
	hintsUc := NewECDetection(ctx, s, conn, myConfig)
	libraries, summary, err := hintsUc.GetDetectionsInRange(componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if len(libraries.Hints[0].Detections) == 0 ||
		len(summary.PurlsFailedToParse) > 0 ||
		len(summary.PurlsWOInfo) > 0 ||
		len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 Hint")
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl: "pkg:github/scanoss/engine",
		},
	}

	libraries, summary, err = hintsUc.GetDetectionsInRange(componentDTOS)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to fail parsing the purl")
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">=1.0",
		},
	}
	libraries, summary, err = hintsUc.GetDetectionsInRange(componentDTOS)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsWOInfo) != 1 {
		t.Fatalf("Expected to not find information for purl")
	}

	tests := []struct {
		name          string
		input         []dtos.ComponentDTO
		expectedError bool
	}{
		{
			name:          "Should_ReturnError_EmptyListOfPurls",
			input:         []dtos.ComponentDTO{},
			expectedError: true,
		},
		{
			name: "Should_ReturnError_RequirementIncludeWildcard",
			input: []dtos.ComponentDTO{
				dtos.ComponentDTO{
					Purl:        "pkg:github/scanoss/engine",
					Requirement: "*",
				},
			},
			expectedError: false,
		},
		{
			name: "Should_ReturnError_RequirementIncludeWildcard",
			input: []dtos.ComponentDTO{
				dtos.ComponentDTO{
					Purl:        "pkg:github/scanoss/engine",
					Requirement: "v*",
				},
			},
			expectedError: false,
		},
		{
			name: "Should_Return_EmptyListOfPurls",
			input: []dtos.ComponentDTO{
				dtos.ComponentDTO{
					Purl: "pkg:github/scanoss/engine",
				},
			},
			expectedError: false,
		},
		{
			name: "Should_Return_Hints",
			input: []dtos.ComponentDTO{
				dtos.ComponentDTO{
					Purl:        "pkg:github/pineappleea/pineapple-src",
					Requirement: ">=0",
				},
				dtos.ComponentDTO{
					Purl:        "pkg:github/pineappleea/pineapple-src",
					Requirement: ">=0",
				},
				dtos.ComponentDTO{
					Purl:        "pkg:github/scanoss/engine",
					Requirement: ">=0",
				},
			},
			expectedError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			libraries, summary, err = hintsUc.GetDetectionsInRange(test.input)
			if (err != nil) != test.expectedError {
				t.Errorf("Test '%s': Expected an error but got nil", test.name)
			}
		})
	}

	componentDTOS = []dtos.ComponentDTO{}
	libraries, summary, err = hintsUc.GetDetectionsInRange(componentDTOS)

	if err == nil {
		t.Fatalf("expected to get an error: %v", err)
	}
	// errors.errorString {s: "empty list of purls"}
	if len(summary.PurlsWOInfo) != 0 {
		t.Fatalf("Expected to not get information of purls")
	}
}

func TestLibrariesDetectionUseCase_ExactVersion(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseConn(conn)
	err = models.LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	var componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/pineappleea/pineapple-src",
			Requirement: "5.4.7",
		},
	}
	hintsUc := NewECDetection(ctx, s, conn, myConfig)
	libraries, summary, err := hintsUc.GetDetections(componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if libraries.Hints[0].Version != "v5.4.7" {
		t.Errorf("Did not receive expected version (5.4.7 expected and received %s)", libraries.Hints[0].Version)
	}
	if len(libraries.Hints[0].Detections) == 0 ||
		len(summary.PurlsFailedToParse) > 0 ||
		len(summary.PurlsWOInfo) > 0 ||
		len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 Hint")
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/pineappleea/pineapple-src",
			Requirement: "5.4.6",
		},
	}
	libraries, summary, err = hintsUc.GetDetections(componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if libraries.Hints[0].Version != "" {
		t.Errorf("Did not receive expected version (5.4.7 expected and received %s)", libraries.Hints[0].Version)
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl: "pkg:github/scanoss/engine",
		},
	}
	libraries, summary, err = hintsUc.GetDetections(componentDTOS)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">=1.0",
		},
	}
	libraries, summary, err = hintsUc.GetDetections(componentDTOS)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsWOInfo) != 1 {
		t.Fatalf("Expected to not find information for purl")
	}

	componentDTOS = []dtos.ComponentDTO{}
	libraries, summary, err = hintsUc.GetDetections(componentDTOS)

	if err == nil {
		t.Fatalf("expected to get an error: %v", err)
	}
	//errors.errorString {s: "empty list of purls"}
	if len(summary.PurlsWOInfo) != 0 {
		t.Fatalf("Expected to not get information of purls")
	}
}
func TestLibrariesDetectionUseCase_MalformedPurl(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseConn(conn)
	err = models.LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	var componentDTO = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:githubscanossengine",
			Requirement: ">=1.0",
		},
	}
	hintsUc := NewECDetection(ctx, s, conn, myConfig)
	libraries, summary, err := hintsUc.GetDetectionsInRange(componentDTO)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to fail parsing 1 purl")
	}
	if len(libraries.Hints) > 0 {
		t.Fatalf("Not expected to get information from an empty request")
	}
}
