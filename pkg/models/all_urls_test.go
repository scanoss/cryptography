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

package models

import (
	"context"
	"fmt"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/utils"
)

func TestAllUrlsSearchVersion(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)

	allUrls, err := allUrlsModel.GetUrlsByPurlNameTypeVersion(ctx, s, "tablestyle", "gem", "0.0.12")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlName() error = %v", err)
	}
	if len(allUrls.PurlName) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeVersion() No URLs returned from query")
	}
	fmt.Printf("All Urls Version: %#v\n", allUrls)

	allUrls, err = allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle@0.0.7", "")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlString() error = failed to find purl by version string")
	}
	fmt.Printf("All Urls Version String: %#v\n", allUrls)

	_, err = allUrlsModel.GetUrlsByPurlNameTypeVersion(ctx, s, "", "", "")
	if err == nil {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = allUrlsModel.GetUrlsByPurlNameTypeVersion(ctx, s, "NONEXISTENT", "", "")
	if err == nil {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = allUrlsModel.GetUrlsByPurlNameTypeVersion(ctx, s, "NONEXISTENT", "NONEXISTENT", "")
	if err == nil {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}

	allUrls, err = allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle", "22.22.22") // Shouldn't exist
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlString() error = failed to find purl by version string")
	} else if len(allUrls.PurlName) > 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() error = Found match, when we shouldn't: %v", allUrls)
	}
}
func TestAllUrlsSearchVersionRequirement(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)
	allUrls, err := allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle", ">0.0.4")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlName() error = %v", err)
	}
	if len(allUrls.PurlName) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() No URLs returned from query")
	}
	fmt.Printf("All Urls Version: %#v\n", allUrls)

	allUrls, err = allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle", "<0.0.4>")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlName() error = %v", err)
	}
	if len(allUrls.PurlName) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() No URLs returned from query")
	}
}

func TestAllUrlsSearchVersionRange(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)

	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)
	allUrls, err := allUrlsModel.GetUrlsByPurlNameTypeInRange(ctx, s, "scanoss/engine", "github", ">2.0")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeInRange() error = %v", err)
	}
	if len(allUrls) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() No URLs returned from query")
	}
	fmt.Printf("All Urls Version: %#v\n", allUrls)

	_, err = allUrlsModel.GetUrlsByPurlNameTypeInRange(ctx, s, "scanoss/engine", "github", "")
	if err == nil {
		t.Errorf("expected error all_urls.GetUrlsByPurlNameTypeInRange() ")
	}

	_, err = allUrlsModel.GetUrlsByPurlNameTypeInRange(ctx, s, "", "github", ">2.0")
	if err == nil {
		t.Errorf("Expected all_urls.GetUrlsByPurlNameTypeInRange() error = %v", err)
	}
	_, err = allUrlsModel.GetUrlsByPurlNameTypeInRange(ctx, s, "scanoss/engine", "", ">2.0")
	if err == nil {
		t.Errorf("Expected all_urls.GetUrlsByPurlNameTypeInRange() error = %v", err)
	}
}

func TestAllUrlsSearchPurlList(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)
	list := []utils.PurlReq{{Purl: "scanoss/engine", Version: "5.4.6"}, {Purl: "scanoss/dependencies", Version: "v0.0.1"}}
	allUrls, err := allUrlsModel.GetUrlsByPurlList(ctx, s, list)
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlNameTypeInRange() error = %v", err)
	}
	if len(allUrls) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() No URLs returned from query")
	}
}

func TestAllUrlsClosestVersionRequirement(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	//allUrlsModel := NewAllURLModel(db)
	allUrls := []AllURL{{URLHash: "0", Component: "engine", PurlName: "scanoss/engine", SemVer: "v1.0", PurlType: "github"},
		{URLHash: "1", Component: "engine", PurlName: "scanoss/engine", SemVer: "v1.1", PurlType: "github"},
		{URLHash: "2", Component: "engine", PurlName: "scanoss/engine", SemVer: "v1.2", PurlType: "github"},
		{URLHash: "3", Component: "engine", PurlName: "scanoss/engine", SemVer: "v1.3", PurlType: "github"},
	}
	_, err = PickClosestUrls(s, allUrls, "scanoss/engine", "github", "v1.3")
	fmt.Printf("%+v", allUrls)
}

func TestAllUrlsSearchNoLicense(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	err = LoadTestSQLData(db, ctx)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)
	allUrls, err := allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle@0.0.8", "")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlString() error = %v", err)
	}
	if len(allUrls.PurlName) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlString() No URLs returned from query")
	}
	fmt.Printf("All (with project) Urls: %#v\n", allUrls)
}

func TestAllUrlsSearchBadSql(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true
	allUrlsModel := NewAllURLModel(db)
	_, err = allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle", "")
	if err == nil {
		t.Errorf("all_urls.GetUrlsByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle@0.0.8", "")
	if err == nil {
		t.Errorf("all_urls.GetUrlsByPurlString() error = did not get an error: %v", err)
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}

	// Load some tables (leaving out projects)
	err = loadTestSQLDataFiles(db, ctx, []string{"./tests/mines.sql", "./tests/all_urls.sql", "./tests/versions.sql"})
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	allUrls, err := allUrlsModel.GetUrlsByPurlString(ctx, s, "pkg:gem/tablestyle@0.0.8", "")
	if err != nil {
		t.Errorf("all_urls.GetUrlsByPurlName() error = %v", err)
	}
	if len(allUrls.PurlName) == 0 {
		t.Errorf("all_urls.GetUrlsByPurlNameType() No URLs returned from query")
	}
	fmt.Printf("All Urls: %v\n", allUrls)
}
