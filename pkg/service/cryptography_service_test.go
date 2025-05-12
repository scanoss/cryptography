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

	server := NewCryptographyServer(db, myConfig)
	r, err := server.GetAlgorithms(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 1 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetAlgorithms(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engines", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}

	r, err = server.GetAlgorithms(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:githubscanossengine", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 0 {
		t.Errorf("Expected to get exactly one purl")
	}
	r, err = server.GetAlgorithms(ctx, &common.PurlRequest{Purls: []*common.PurlRequest_Purls{{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"}, {Purl: "pkg:github/scanoss/dependencies", Requirement: "v5.4.5"}}})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if len(r.Purls) != 2 {
		t.Errorf("Expected to get exactly one purl")
	} else if !strings.Contains(r.Status.Message, "Can't find information for 1 purl(s)") {
		t.Errorf("Status message does not match")
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
