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

func TestLibrariesDetectionUseCase(t *testing.T) {
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
	var cryptoRequest = `{
			   "purls": [
				 {
				   "purl": "pkg:github/pineappleea/pineapple-src",
				   "requirement":">=0"
				   
				 }
			   ]
			   }`
	hintsUc := NewECDetection(ctx, s, conn, myConfig)

	requestDto, err := dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	libraries, summary, err := hintsUc.GetDetectionsInRange(requestDto)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting Hints", err)
	}
	if len(libraries.Hints[0].Detections) == 0 ||
		len(summary.PurlsFailedToParse) > 0 ||
		len(summary.PurlsWOInfo) > 0 ||
		len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 Hint")
	}

	var unExistentRequirement = `{
					"purls": [
						{
						  "purl":"pkg:github/scanoss/engine"
						}
				  ]
				}
			`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(unExistentRequirement))

	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	libraries, summary, err = hintsUc.GetDetectionsInRange(requestDto)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to fail parsing the purl")
	}
	var unExistentHints = `{
		"purls": [
			{
			  "purl":"pkg:github/scanoss/engine",
			  "requirement":">=1.0"
			}
	  ]
	}
`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(unExistentHints))

	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	libraries, summary, err = hintsUc.GetDetectionsInRange(requestDto)

	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsWOInfo) != 1 {
		t.Fatalf("Expected to not find information for purl")
	}

	var emptyRequest = `{
		"purls": [
			 ]
	}
`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(emptyRequest))

	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	libraries, summary, err = hintsUc.GetDetectionsInRange(requestDto)

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

	var malformedPurls = `{
		"purls": [
			{
			  "purl":"pkg:githubscanossengine",
			  "requirement":">=1.0"
			}
	  ]
	}
`
	hintsUc := NewECDetection(ctx, s, conn, myConfig)
	requestDto, err := dtos.ParseCryptoInput(s, []byte(malformedPurls))

	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	libraries, summary, err := hintsUc.GetDetectionsInRange(requestDto)

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
