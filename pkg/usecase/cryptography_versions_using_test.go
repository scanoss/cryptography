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
	var cryptoRequest = `{
		      "purls": [
		        {
		          "purl": "pkg:github/scanoss/engine",
				  "requirement":">v2.0.0"
		          
		        },
				{
				   "purl": "pkg:github/scanoss/dependencies",
				   "requirement":">v0.0" }
		      ]
		  	}`
	versionsUc := NewVersionsUsingCrypto(ctx, s, conn, myConfig)

	requestDto, err := dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err := versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
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

	var emptyRequest = `{
		"purls": [
		  
		]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(emptyRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if err == nil {
		t.Fatalf("Expected to get an 'Empty list' error")
	}

	var malformedPurl = `{
		"purls": [
		  {
			"purl": "pkg:githubscanossengine",
			"requirement":">v5.3"
			
		  }
		]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(malformedPurl))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if len(versions.Versions) != 0 {
		t.Fatalf("Not Expected to receive versions")
	}
	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to get exactly one purl failed to parse and received %d", len(summary.PurlsFailedToParse))
	}

	var notAllowedRange = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engine",
			"requirement":"*"
			
		  }
		]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(notAllowedRange))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if err == nil {
		t.Fatalf("An invalid range error was expected")
	}
	if len(versions.Versions) != 0 {
		t.Fatalf("Not Expected to receive versions")
	}
	var listWithInvalidPurl = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engine",
			"requirement":">5.3"			
		  },
		  {
			"purl": "pkg:githubscanossminr",
			"requirement":">1.3"			
		  }
		]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(listWithInvalidPurl))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsFailedToParse) != 1 {
		t.Fatalf("Expected to get exactly one purl failed to parse and received %d", len(summary.PurlsFailedToParse))
	}

	var purlNotFound = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engines",
			"requirement":">5.3"			
		  }
		 ]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(purlNotFound))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsNotFound) != 1 {
		t.Fatalf("Expected to get exactly one purl not found and received %d", len(summary.PurlsFailedToParse))
	}

	var noRequirement = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engine"
					
		  }
		 ]
		}`

	requestDto, err = dtos.ParseCryptoInput(s, []byte(noRequirement))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	versions, summary, err = versionsUc.GetVersionsInRangeUsingCrypto(requestDto)
	if err != nil {
		t.Fatalf("error was not expected")
	}
	if len(summary.PurlsNotFound) != 1 {
		t.Fatalf("Expected to get exactly one purl not found and received %d", len(summary.PurlsFailedToParse))
	}

	/*if len(versions.Versions[0].VersionsWith) != 3 {
		t.Fatalf("expected to get 3 versions with crypto and received %d\n", len(versions.Versions[0].VersionsWith))
	}
	if len(versions.Versions[0].VersionsWithout) != 0 {
		t.Fatalf("Not expected to get versions without crypto %d\n", len(versions.Versions[0].VersionsWith))
	}

	/* dtos.VersionsInRangeUsingCryptoItem {Purl: "pkg:github/scanoss/engine", VersionsWith: []string len: 3, cap: 4, ["5.4.5","5.4.6","5.4.7"], VersionsWithout: []string len: 0, cap: 0, []}
	*/

	_ = summary
	/*if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 3 {
		t.Fatalf("Expected to receive  3 versions")
	}

	if len(algorithms.Cryptography[0].Algorithms) == 0 || len(summary.PurlsNotFound) > 0 {
		t.Fatalf("Expected to get at least 1 algorithm")
	}

	algorithms, summary, err = cryptoUc.GetCryptoInRange(requestDto)
	if err != nil {
		t.Fatalf("error not expected: %v", err)
	}
	if len(summary.PurlsFailedToParse) > 0 {
		t.Fatal("Expected to get All purls")
	}

	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 3 {
		t.Fatalf("Expected to receive  2 versions")
	}

	cryptoRequest = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engine",
			"requirement":">v5.4.5,<5.4.7"

		  }
		]
		}`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	algorithms, summary, err = cryptoUc.GetCryptoInRange(requestDto)
	if err != nil {
		t.Fatalf("error not expected: %v", err)
	}
	if len(summary.PurlsNotFound) > 0 {
		t.Fatal("Expected to get All purls")
	}

	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 1 {
		t.Fatalf("Expected to receive  2 versions")
	}*/
}

// TODO: Implement this test
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
	var cryptoRequest = `{
		      "purls": [
		        {
		          "purl": "pkg:github/scanoss/engine",
				  "requirement":">v5.3"
		          
		        }
		      ]
		  	}`
	cryptoUc := NewCryptoMajor(ctx, s, conn, myConfig)

	requestDto, err := dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	algorithms, summary, err := cryptoUc.GetCryptoInRange(requestDto)
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

	algorithms, summary, err = cryptoUc.GetCryptoInRange(requestDto)
	if err != nil {
		t.Fatalf("error not expected: %v", err)
	}
	if len(summary.PurlsFailedToParse) > 0 {
		t.Fatal("Expected to get All purls")
	}

	if len(algorithms.Cryptography[0].Versions) == 0 || len(algorithms.Cryptography[0].Versions) != 3 {
		t.Fatalf("Expected to receive  2 versions")
	}

	cryptoRequest = `{
		"purls": [
		  {
			"purl": "pkg:github/scanoss/engine",
			"requirement":">v5.4.5,<5.4.7"
			
		  }
		]
		}`
	requestDto, err = dtos.ParseCryptoInput(s, []byte(cryptoRequest))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}

	algorithms, summary, err = cryptoUc.GetCryptoInRange(requestDto)
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
