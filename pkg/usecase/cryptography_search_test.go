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

func TestCryptographyUseCase(t *testing.T) {
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
	cryptoUc := NewCrypto(db, myConfig)
	var componentDTOS = []dtos.ComponentDTO{
		{
			Purl: "pkg:github/scanoss/engine",
		},
	}
	algorithms, err := cryptoUc.GetComponentsAlgorithms(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting cryptography", err)
	}
	for _, c := range algorithms.Cryptography {
		if c.Status.StatusCode != status.Success {
			t.Fatalf("Expected to get at least 1 algorithm")
		}
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl: "pkg:npm/",
		},
	}
	algorithms, err = cryptoUc.GetComponentsAlgorithms(ctx, s, componentDTOS)
	for _, c := range algorithms.Cryptography {
		if c.Status.StatusCode != status.InvalidPurl {
			t.Fatalf("did not get an expected purl failed to parse")
		}
	}
	// t.Logf("Got expected error: %+v\n", err)
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: "v5.9.0",
		},
	}
	algorithms, err = cryptoUc.GetComponentsAlgorithms(ctx, s, componentDTOS)
	for _, c := range algorithms.Cryptography {
		if c.Status.StatusCode == status.InvalidPurl {
			t.Fatalf("did not get an expected purl failed to parse")
		}
	}

	componentDTOS = []dtos.ComponentDTO{
		{
			Purl: "pkg:github/scanoss/engines",
		},
	}
	algorithms, err = cryptoUc.GetComponentsAlgorithms(ctx, s, componentDTOS)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}
	for _, c := range algorithms.Cryptography {
		if c.Status.StatusCode != status.ComponentNotFound {
			t.Fatalf("Expected to not found a purl")
		}
	}
}
