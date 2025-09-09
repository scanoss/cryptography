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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"

	"github.com/jmoiron/sqlx"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/models"
)

func TestCryptographyServer_Echo(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
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

	server := NewCryptographyServer(db, myConfig)

	type args struct {
		ctx context.Context
		req *common.EchoRequest
	}
	tests := []struct {
		name    string
		s       pb.CryptographyServer
		args    args
		want    *common.EchoResponse
		wantErr bool
	}{
		{
			name: "Echo",
			s:    server,
			args: args{
				ctx: ctx,
				req: &common.EchoRequest{Message: "Hello there!"},
			},
			want: &common.EchoResponse{Message: "Hello there!"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.Echo(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Echo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("service.Echo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCryptographyServer_GetAlgorithms(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	invalidDB, err := sqlx.Connect("sqlite", ":memory:")
	invalidDB.Close()

	tests := []struct {
		name                 string
		req                  string
		request              string
		expectedPurls        int
		expectedError        bool
		status               common.StatusCode
		expectedErrorMessage string
		db                   *sqlx.DB
	}{
		{
			name:                 "Should_Return_ResponseWithOnePurl",
			request:              `{"purls": [{"purl": "pkg:github/scanoss/engine", "requirement":"v5.4.5"}]}`,
			expectedPurls:        1,
			expectedError:        false,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
			db:                   db,
		},
		{
			name:                 "Should_Return_CantFindPurl",
			request:              `{"purls": [{"purl": "pkg:github/scanoss/engines", "requirement":"v5.4.5"}]}`,
			expectedPurls:        0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
			db:                   db,
		},
		{
			name:                 "Should_Return_FailedToParsePurl",
			request:              `{"purls": [{"purl": "pkg:githubscanossengine", "requirement":"v5.4.5"}]}`,
			expectedPurls:        0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):pkg:githubscanossengine",
			db:                   db,
		},
		{
			name:                 "Should_Return_ResponseWithTwoPurls",
			request:              `{"purls": [{"purl": "pkg:github/scanoss/engine", "requirement":"v5.4.5"}, {"purl": "pkg:github/scanoss/dependencies", "requirement": "v5.4.5"}]}`,
			expectedPurls:        2,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find information for 1 purl(s):scanoss/dependencies",
			db:                   db,
		},
		{
			name:                 "Should_Return_NoDataSupplied",
			request:              `{"purls":[]}`,
			expectedError:        true,
			expectedPurls:        0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "No purls in request data supplied",
			db:                   db,
		},
		{
			name:                 "Should_Return_NoDataSupplied",
			request:              `{"purls":[{"purl":""}]}`,
			expectedError:        false,
			expectedPurls:        0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name:                 "Should_ReturnError_NoDBConnection",
			request:              `{"purls": [{"purl": "pkg:github/scanoss/engine", "requirement":"v5.4.5"}]}`,
			expectedError:        true,
			expectedPurls:        0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "Failed to get database pool connection",
			db:                   invalidDB,
		},
		{
			name:                 "Should_ReturnError_InvalidJSON",
			request:              `{"purls": [{"purl": "pkg:github/scanoss/engine", "requirement": [],}]}`,
			expectedError:        true,
			expectedPurls:        0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "No purls in request data supplied",
			db:                   db,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewCryptographyServer(tt.db, myConfig)
			var req common.PurlRequest
			err = json.Unmarshal([]byte(tt.request), &req)
			r, err := server.GetAlgorithms(ctx, &req)
			if (err != nil) != tt.expectedError {
				t.Errorf("service.GetAlgorithms() error = %v, wantErr %v", err, tt.expectedError)
			}
			if len(r.Purls) != tt.expectedPurls {
				t.Errorf("expected to get exactly %d purl, but received %d", tt.expectedPurls, len(r.Purls))
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetAlgorithms(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetAlgorithms(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}

		})
	}
}

func TestCryptographyServer_GetAlgorithmsInRange(t *testing.T) {

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)
	r, err := server.GetAlgorithmsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetAlgorithmsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetAlgorithmsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}
	r, err = server.GetAlgorithmsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}, {Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	} else if !strings.Contains(r.Status.Message, "Can't find 1 purl(s)") {
		t.Errorf("Status message does not match")
	}
}
func TestCryptographyServer_GetVersionsInRange(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)
	r, err := server.GetVersionsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetVersionsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetVersionsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}
	r, err = server.GetVersionsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}, {Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	} else if !strings.Contains(r.Status.Message, "Can't find 1 purl(s)") {
		t.Errorf("Status message does not match")
	}
}

func TestCryptographyServer_GetHintsInRange(t *testing.T) {

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)
	r, err := server.GetHintsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetHintsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetHintsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}
	r, err = server.GetHintsInRange(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}, {Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	} else if !strings.Contains(r.Status.Message, "Can't find 1 purl(s)") {
		t.Errorf("Status message does not match")
	}
}

func TestCryptographyServer_GetHints(t *testing.T) {

	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)
	r, err := server.GetEncryptionHints(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/pineappleea/pineapple-src", Requirement: "v5.4.7"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetEncryptionHints(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/pineappleea/pineapple-src1", Requirement: "v5.4.7"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}
	if r.Status.Status != 2 {
		t.Errorf("Error retrieving status")
	}

	r, err = server.GetEncryptionHints(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Did not expect to receive a malformed purl")
	}
	r, err = server.GetEncryptionHints(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}, {Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 2 {
		t.Errorf("Expected to get exactly one purl")
	} else if !strings.Contains(r.Status.Message, "Can't find information") {
		t.Errorf("Status message does not match")
	}
}

func TestCryptographyServer_GetComponentsAlgorithms(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	invalidDB, err := sqlx.Connect("sqlite", ":memory:")
	invalidDB.Close()

	tests := []struct {
		name                 string
		components           []*common.ComponentRequest
		expectedComponents   int
		expectedError        bool
		status               common.StatusCode
		expectedErrorMessage string
		db                   *sqlx.DB
	}{
		{
			name: "Should_Return_ResponseWithOneComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			},
			expectedComponents:   1,
			expectedError:        false,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
			db:                   db,
		},
		{
			name: "Should_Return_CantFindComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"},
			},
			expectedComponents:   0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
			db:                   db,
		},
		{
			name: "Should_Return_FailedToParseComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"},
			},
			expectedComponents:   0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name: "Should_Return_ResponseWithTwoComponents",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				{Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"},
			},
			expectedComponents:   1,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/dependencies",
			db:                   db,
		},
		{
			name:                 "Should_Return_NoDataSupplied",
			components:           []*common.ComponentRequest{},
			expectedError:        true,
			expectedComponents:   0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "No purls in request data supplied",
			db:                   db,
		},
		{
			name: "Should_Return_EmptyPurl",
			components: []*common.ComponentRequest{
				{Purl: "", Requirement: "v5.4.5"},
			},
			expectedError:        false,
			expectedComponents:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name: "Should_ReturnError_NoDBConnection",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			},
			expectedError:        true,
			expectedComponents:   0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "Failed to get database pool connection",
			db:                   invalidDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewCryptographyServer(tt.db, myConfig)
			req := &common.ComponentsRequest{Components: tt.components}

			r, err := server.GetComponentsAlgorithms(ctx, req)
			if (err != nil) != tt.expectedError {
				t.Errorf("service.GetComponentsAlgorithms() error = %v, wantErr %v", err, tt.expectedError)
			}
			if len(r.Components) != tt.expectedComponents {
				t.Errorf("expected to get exactly %d components, but received %d", tt.expectedComponents, len(r.Components))
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentsAlgorithms(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentsAlgorithms(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}

func TestCryptographyServer_GetComponentAlgorithms(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	invalidDB, err := sqlx.Connect("sqlite", ":memory:")
	invalidDB.Close()

	tests := []struct {
		name                 string
		component            *common.ComponentRequest
		hasComponent         bool
		expectedError        bool
		status               common.StatusCode
		expectedErrorMessage string
		db                   *sqlx.DB
	}{
		{
			name:                 "Should_Return_ResponseWithOneComponent",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
			db:                   db,
		},
		{
			name:                 "Should_Return_CantFindComponent",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
			db:                   db,
		},
		{
			name:                 "Should_Return_FailedToParseComponent",
			component:            &common.ComponentRequest{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name:                 "Should_Return_EmptyPurl",
			component:            &common.ComponentRequest{Purl: "", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name:                 "Should_ReturnError_NoDBConnection",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			hasComponent:         false,
			expectedError:        true,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "Failed to get database pool connection",
			db:                   invalidDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewCryptographyServer(tt.db, myConfig)

			r, err := server.GetComponentAlgorithms(ctx, tt.component)
			if (err != nil) != tt.expectedError {
				t.Errorf("service.GetComponentAlgorithms() error = %v, wantErr %v", err, tt.expectedError)
			}
			if tt.hasComponent && r.Component == nil {
				t.Errorf("expected to get a component, but received nil")
			} else if !tt.hasComponent && r.Component != nil {
				t.Errorf("expected not to get a component, but received one")
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentAlgorithms(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentAlgorithms(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}

func TestCryptographyServer_GetComponentsAlgorithmsInRange(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	invalidDB, err := sqlx.Connect("sqlite", ":memory:")
	invalidDB.Close()

	tests := []struct {
		name                 string
		components           []*common.ComponentRequest
		expectedComponents   int
		expectedError        bool
		status               common.StatusCode
		expectedErrorMessage string
		db                   *sqlx.DB
	}{
		{
			name: "Should_Return_ResponseWithOneComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			},
			expectedComponents:   1,
			expectedError:        false,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
			db:                   db,
		},
		{
			name: "Should_Return_CantFindComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"},
			},
			expectedComponents:   0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
			db:                   db,
		},
		{
			name: "Should_Return_FailedToParseComponent",
			components: []*common.ComponentRequest{
				{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"},
			},
			expectedComponents:   0,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name: "Should_Return_ResponseWithTwoComponents",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				{Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"},
			},
			expectedComponents:   1,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/dependencies",
			db:                   db,
		},
		{
			name:                 "Should_Return_NoDataSupplied",
			components:           []*common.ComponentRequest{},
			expectedError:        true,
			expectedComponents:   0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "No purls in request data supplied",
			db:                   db,
		},
		{
			name: "Should_Return_EmptyPurl",
			components: []*common.ComponentRequest{
				{Purl: "", Requirement: "v5.4.5"},
			},
			expectedError:        false,
			expectedComponents:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name: "Should_ReturnError_NoDBConnection",
			components: []*common.ComponentRequest{
				{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			},
			expectedError:        true,
			expectedComponents:   0,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "Failed to get database pool connection",
			db:                   invalidDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewCryptographyServer(tt.db, myConfig)
			req := &common.ComponentsRequest{Components: tt.components}

			r, err := server.GetComponentsAlgorithmsInRange(ctx, req)
			if (err != nil) != tt.expectedError {
				t.Errorf("service.GetComponentsAlgorithmsInRange() error = %v, wantErr %v", err, tt.expectedError)
			}
			if len(r.Components) != tt.expectedComponents {
				t.Errorf("expected to get exactly %d components, but received %d", tt.expectedComponents, len(r.Components))
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentsAlgorithmsInRange(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentsAlgorithmsInRange(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}

func TestCryptographyServer_GetComponentAlgorithmsInRange(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	invalidDB, err := sqlx.Connect("sqlite", ":memory:")
	invalidDB.Close()

	tests := []struct {
		name                 string
		component            *common.ComponentRequest
		hasComponent         bool
		expectedError        bool
		status               common.StatusCode
		expectedErrorMessage string
		db                   *sqlx.DB
	}{
		{
			name:                 "Should_Return_ResponseWithOneComponent",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
			db:                   db,
		},
		{
			name:                 "Should_Return_CantFindComponent",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
			db:                   db,
		},
		{
			name:                 "Should_Return_FailedToParseComponent",
			component:            &common.ComponentRequest{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name:                 "Should_Return_EmptyPurl",
			component:            &common.ComponentRequest{Purl: "", Requirement: "v5.4.5"},
			hasComponent:         true,
			expectedError:        false,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
			db:                   db,
		},
		{
			name:                 "Should_ReturnError_NoDBConnection",
			component:            &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			hasComponent:         false,
			expectedError:        true,
			status:               common.StatusCode_FAILED,
			expectedErrorMessage: "Failed to get database pool connection",
			db:                   invalidDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewCryptographyServer(tt.db, myConfig)

			r, err := server.GetComponentAlgorithmsInRange(ctx, tt.component)
			if (err != nil) != tt.expectedError {
				t.Errorf("service.GetComponentAlgorithmsInRange() error = %v, wantErr %v", err, tt.expectedError)
			}
			if tt.hasComponent && r.Component == nil {
				t.Errorf("expected to get a component, but received nil")
			} else if !tt.hasComponent && r.Component != nil {
				t.Errorf("expected not to get a component, but received one")
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentAlgorithmsInRange(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentAlgorithmsInRange(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}

func TestCryptographyServer_GetComponentVersionsInRange(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)

	tests := []struct {
		name                 string
		request              *common.ComponentRequest
		expectedPurlsCount   int
		status               common.StatusCode
		expectedErrorMessage string
	}{
		{
			name: "Should_Return_ResponseWithOneComponent",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/scanoss/engine",
				Requirement: "v5.4.5",
			},
			expectedPurlsCount:   1,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
		},
		{
			name: "Should_Return_CantFindComponent",
			request: &common.ComponentRequest{
				Purl:        "pkg:github/scanoss/engines",
				Requirement: "v5.4.5",
			},
			expectedPurlsCount:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
		},
		{
			name: "Should_Return_FailedToParsePurl",
			request: &common.ComponentRequest{
				Purl:        "pkg:githubscanossengine",
				Requirement: "v5.4.5",
			},
			expectedPurlsCount:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := server.GetComponentVersionsInRange(ctx, tt.request)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentVersionsInRange(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentVersionsInRange(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}

func TestCryptographyServer_GetComponentsVersionsInRange(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseDB(db)
	ctx = ctxzap.ToContext(ctx, zlog.L)

	err = models.LoadTestSQLData(db, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	server := NewCryptographyServer(db, myConfig)

	tests := []struct {
		name                 string
		request              *common.ComponentsRequest
		expectedPurlsCount   int
		status               common.StatusCode
		expectedErrorMessage string
	}{
		{
			name: "Should_Return_ResponseWithOneComponent",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				},
			},
			expectedPurlsCount:   1,
			status:               common.StatusCode_SUCCESS,
			expectedErrorMessage: "Success",
		},
		{
			name: "Should_Return_CantFindComponent",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"},
				},
			},
			expectedPurlsCount:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/engines",
		},
		{
			name: "Should_Return_FailedToParsePurl",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"},
				},
			},
			expectedPurlsCount:   0,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Failed to parse 1 purl(s):",
		},
		{
			name: "Should_Return_ResponseWithTwoComponents",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
					{Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"},
				},
			},
			expectedPurlsCount:   1,
			status:               common.StatusCode_SUCCEEDED_WITH_WARNINGS,
			expectedErrorMessage: "Can't find 1 purl(s):scanoss/dependencies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := server.GetComponentsVersionsInRange(ctx, tt.request)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(r.Components) != tt.expectedPurlsCount {
				t.Errorf("Expected to get exactly %d components, got %d", tt.expectedPurlsCount, len(r.Components))
			}
			if tt.status != r.Status.Status {
				t.Errorf("service.GetComponentsVersionsInRange(),received = %v, want %v", r.Status.Status, tt.status)
			}
			if r.Status.Message != tt.expectedErrorMessage {
				t.Errorf("service.GetComponentsVersionsInRange(), received %v, want %v", r.Status.Message, tt.expectedErrorMessage)
			}
		})
	}
}
