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
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/testutils"
)

func TestLibrariesDetectionUseCase_InRange(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

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
	err = models.LoadTestSQLData(db, ctx)
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
			Requirement: ">=0.0.0",
		},
	}
	hintsUc := NewECDetection(db, myConfig)
	libraries, err := hintsUc.GetDetectionsInRange(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	for _, h := range libraries.Hints {
		if h.Status.StatusCode != status.Success {
			t.Fatalf("Expected to get a success status")
		}
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl: "pkg:github/scanoss/engine",
		},
	}

	libraries, err = hintsUc.GetDetectionsInRange(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}
	for _, h := range libraries.Hints {
		if h.Status.StatusCode != status.InvalidSemver {
			t.Fatalf("Expected to get invalid semver status, get %s", h.Status.StatusCode)
		}
	}

	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">=1.0.0",
		},
	}
	libraries, err = hintsUc.GetDetectionsInRange(ctx, s, componentDTOS)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}
	for _, h := range libraries.Hints {
		if h.Status.StatusCode != status.NoInfo {
			t.Fatalf("Expected to not find information for purl")
		}
	}
}

func TestLibrariesDetectionUseCase_ExactVersion(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

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
	err = models.LoadTestSQLData(db, ctx)
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
	hintsUc := NewECDetection(db, myConfig)
	libraries, err := hintsUc.GetDetections(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if libraries.Hints[0].Version != "v5.4.7" {
		t.Errorf("Did not receive expected version (5.4.7 expected and received %s)", libraries.Hints[0].Version)
	}
	for _, c := range libraries.Hints {
		if c.Status.StatusCode != status.Success {
			t.Fatalf("Expected to get at least 1 Hint")
		}
	}

	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/pineappleea/pineapple-src",
			Requirement: "5.4.6",
		},
	}
	libraries, err = hintsUc.GetDetections(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if libraries.Hints[0].Version != "" {
		t.Errorf("Did not receive expected version (5.4.7 expected and received %s)", libraries.Hints[0].Version)
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl: "pkg:github/scanoss/engine",
		},
	}
	libraries, err = hintsUc.GetDetections(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">=1.0",
		},
	}
	libraries, err = hintsUc.GetDetections(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}
	for _, c := range libraries.Hints {
		if c.Status.StatusCode != status.NoInfo {
			t.Fatalf("Expected to not find information for purl")
		}
	}
}
func TestLibrariesDetectionUseCase_MalformedPurl(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

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
	err = models.LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	var componentDTO = []dtos.ComponentDTO{
		{
			Purl:        "pkg:githubscanossengine",
			Requirement: ">=1.0",
		},
	}
	hintsUc := NewECDetection(db, myConfig)
	libraries, err := hintsUc.GetDetectionsInRange(ctx, s, componentDTO)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	for _, c := range libraries.Hints {
		if c.Status.StatusCode != status.InvalidPurl {
			t.Fatalf("Expected to fail parsing 1 purl")
		}
	}
}
