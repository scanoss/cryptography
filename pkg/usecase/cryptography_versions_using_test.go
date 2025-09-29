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

func TestVersionsUsingCryptoUseCase(t *testing.T) {
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
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">v2.0.0",
		},
		{
			Purl:        "pkg:github/scanoss/dependencies",
			Requirement: ">v0.0.0",
		},
	}
	versionsUc := NewVersionsUsingCrypto(ctx, s, conn, myConfig)

	versions, summary, err := versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting cryptography", err)
	}
	if len(versions.Versions) == 0 {
		t.Fatalf("Expected to receive versions")
	}
	if len(versions.Versions[0].VersionsWith) != 4 {
		t.Fatalf("expected to get 3 versions with crypto and received %d\n", len(versions.Versions[0].VersionsWith))
	}
	if len(versions.Versions[0].VersionsWithout) != 1 {
		t.Fatalf("Expected to get 1 versions without crypto and found %d\n", len(versions.Versions[0].VersionsWithout))
	}

	componentDTOS = []dtos.ComponentDTO{}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err == nil {
		t.Fatalf("Expected to get an 'Empty list' error")
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:githubscanossengine",
			Requirement: ">v5.3.0",
		},
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if len(versions.Versions) != 0 {
		t.Fatalf("Not Expected to receive versions")
	}
	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to get exactly one purl failed to parse and received %d", len(summary.PurlsFailedToParse))
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: "*",
		},
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err == nil {
		t.Fatalf("An invalid range error was expected")
	}
	if len(versions.Versions) != 0 {
		t.Fatalf("Not Expected to receive versions")
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">5.3.0",
		},
		{
			Purl:        "pkg:githubscanossminr",
			Requirement: ">1.3.0",
		},
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to get exactly one purl failed to parse and received %d", len(summary.PurlsFailedToParse))
	}
	componentDTOS = []dtos.ComponentDTO{
		{
			Purl:        "pkg:github/scanoss/engines",
			Requirement: ">5.3.0",
		},
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsNotFound) != 1 {
		t.Fatalf("Expected to get exactly one purl not found and received %d", len(summary.PurlsFailedToParse))
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl: "pkg:github/scanoss/engine",
		},
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(componentDTOS)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsNotFound) != 1 {
		t.Fatalf("Expected to get exactly one purl not found and received %d", len(summary.PurlsFailedToParse))
	}
}

func TestVersionInRangeUsingCryptoUseCase(t *testing.T) {
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
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">5.3.0",
		},
	}

	cryptoUc := NewCryptoMajor(ctx, s, conn, myConfig)
	algorithms, summary, err := cryptoUc.GetCryptoInRange(componentDTOS)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting cryptography", err)
	}
	if len(algorithms.Cryptography) == 0 {
		t.Fatalf("Expected to receive  1 purl")
	}
	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 3 {
		t.Fatalf("Expected to receive  3 versions")
	}

	if len(algorithms.Cryptography[0].Algorithms) == 0 || len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 algorithm")
	}

	algorithms, summary, err = cryptoUc.GetCryptoInRange(componentDTOS)
	if err != nil {
		t.Fatalf("error not expected: %v", err)
	}
	if len(summary.PurlsFailedToParse) > 0 {
		t.Fatal("Expected to get All purls")
	}

	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 3 {
		t.Fatalf("Expected to receive  2 versions")
	}
	componentDTOS = []dtos.ComponentDTO{
		dtos.ComponentDTO{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">v5.4.5,<5.4.7",
		},
	}
	algorithms, summary, err = cryptoUc.GetCryptoInRange(componentDTOS)
	if err != nil {
		t.Fatalf("error not expected: %v", err)
	}
	if len(summary.PurlsNotFound) > 0 {
		t.Fatal("Expected to get All purls")
	}

	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 1 {
		t.Fatalf("Expected to receive  2 versions")
	}
}
