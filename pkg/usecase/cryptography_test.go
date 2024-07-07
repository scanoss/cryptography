// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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
	"fmt"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
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
	db, err := sqlx.Connect("sqlite3", ":memory:")
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
	myConfig.LDB.LdbPath = "../../test-support/ldb"
	myConfig.LDB.Binary = "../../test-support/ldb.sh"
	myConfig.LDB.Debug = true
	var cryptoRequest = `{
		      "purls": [
		        {
		          "purl": "pkg:maven/org.bouncycastle/bcutil-lts8on",
		          "requirement": "2.73.2"
		        }
		      ]
		  	}`
	cryptoUc := NewCrypto(ctx, s, conn, myConfig)

	requestDto, err := dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, notFound, err := cryptoUc.GetCrypto(requestDto)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when getting cryptography", err)
	}
	fmt.Printf("Algorithms: %v", algorithms)

	if len(algorithms.Cryptography[0].Algorithms) == 0 {
		t.Fatalf("Expected to get at least 1 algorithm")
	}
	fmt.Printf("Cryptography response: %+v, %d\n", algorithms, notFound)
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
	algorithms, _, err = cryptoUc.GetCrypto(requestDto)
	if err == nil {
		t.Fatalf("did not get an expected error: %v", algorithms)
	}
	fmt.Printf("Got expected error: %+v\n", err)

	var cryptoAmbiguousRequest = `{
		"purls": [
			{
			  "purl":"pkg:maven/org.bouncycastle/bcutil-lts8on@2.73.2"
			}
	  ]
	}
	`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(cryptoAmbiguousRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, notFound, err = cryptoUc.GetCrypto(requestDto)
	if err != nil {
		t.Fatalf("did not get an expected error: %v", algorithms)
	}
	if notFound > 0 {
		t.Fatalf("Expected to retrieve at least one url")
	}
	if len(algorithms.Cryptography[0].Algorithms) == 0 {
		t.Fatalf("Expected to disambiguate urls and retrieve at least one algorithm")
	}
}
