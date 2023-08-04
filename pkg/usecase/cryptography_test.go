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
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	zlog "scanoss.com/cryptography/pkg/logger"
	"scanoss.com/cryptography/pkg/models"
)

func TestCryptographyUseCase(t *testing.T) {

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := context.Background()
	ctx = ctxzap.ToContext(ctx, zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	_ = s
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
	err = models.LoadTestSqlData(db, ctx, conn)
	models.LDBPivotTableName = "oss/pivot"
	models.LDBCryptoTableName = "quique/ncrypto"
	models.LDBBinPath = "/home/scanoss/Quique/cryptography/./ldb"
	if err != nil {
		t.Fatalf("an error '%s' was not expected when loading test data", err)
	}
	var cryptoRequest = `{
		      "purls": [
		        {
		          "purl": "pkg:github/scanoss/engine",
		          "requirement": "5.2.4"
		        }
		      ]
		  	}`
	myConfig, err := myconfig.NewServerConfig(nil)
	_ = myConfig
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	cryptoUc := NewCrypto(ctx, conn)
	requestDto, err := dtos.ParseCryptoInput([]byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, notFound, err := cryptoUc.GetCrypto(requestDto)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when getting cryptography", err)
	}
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

	requestDto, err = dtos.ParseCryptoInput([]byte(cryptoBadRequest))

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

	requestDto, err = dtos.ParseCryptoInput([]byte(cryptoAmbiguousRequest))

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
