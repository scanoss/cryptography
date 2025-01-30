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

func TestCryptographyUseCase(t *testing.T) {
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
		          "purl": "pkg:github/scanoss/engine"
		          
		        }
		      ]
		  	}`
	cryptoUc := NewCrypto(ctx, s, conn, myConfig)

	requestDto, err := dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, summary, err := cryptoUc.GetCrypto(requestDto)
	if err != nil {
		t.Fatalf("the error '%v' was not expected when getting cryptography", err)
	}
	t.Logf("Algorithms: %v", algorithms)

	if len(algorithms.Cryptography[0].Algorithms) == 0 ||
		len(summary.PurlsFailedToParse) > 0 ||
		len(summary.PurlsWOInfo) > 0 ||
		len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 algorithm")
	}

	var cryptoBadRequest = `{
	   		    "purls": [
	   		        {
	   		          "purl": "pkg:npm/"
	   		        }
	   		  ]
	   		}
	   		`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(cryptoBadRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, summary, err = cryptoUc.GetCrypto(requestDto)
	if len(summary.PurlsFailedToParse) == 0 {
		t.Fatalf("did not get an expected purl failed to parse")
	}
	//t.Logf("Got expected error: %+v\n", err)
	var closestUrl = `{
		"purls": [
			{
			  "purl": "pkg:github/scanoss/engine",
			  "requirement":"v5.9.0"
			}
	  ]
	}
	`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(closestUrl))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, summary, err = cryptoUc.GetCrypto(requestDto)

	if len(summary.PurlsFailedToParse) != 0 {
		t.Fatalf("did not get an expected purl failed to parse")
	}

	var unExistentPurlRequest = `{
	   		"purls": [
	   			{
	   			  "purl":"pkg:github/scanoss/engines"
	   			}
	   	  ]
	   	}
	   `
	requestDto, err = dtos.ParseCryptoInput(s, []byte(unExistentPurlRequest))

	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	algorithms, summary, err = cryptoUc.GetCrypto(requestDto)
	t.Logf("%+v - %v\n", summary, err)
	if err != nil {
		t.Fatalf("Got an unexpected error: %v", err)
	}

	if len(summary.PurlsNotFound) == 0 {
		t.Fatalf("Expected to not found a purl")
	}
}
