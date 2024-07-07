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

package models

import (
	"context"
	"fmt"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	myconfig "scanoss.com/cryptography/pkg/config"
)

const (
	ldbPath      = "../../test-support/ldb"
	ldbBinary    = "../../test-support/ldb.sh"
	doesNotExist = "does-not-exist"
)

func TestPingLDB_Pass(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = ldbPath
	myConfig.LDB.Binary = ldbBinary
	ldbModel := NewLdbModel(context.Background(), s, myConfig)
	err = ldbModel.PingLDB([]string{myConfig.LDB.CryptoTable, myConfig.LDB.PivotTable})
	if err != nil {
		t.Fatalf("LDB does not exist: %v", err)
	}
}

func TestPingLDB_Fail(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = doesNotExist
	myConfig.LDB.Binary = doesNotExist
	ldbModel := NewLdbModel(context.Background(), s, myConfig)
	err = ldbModel.PingLDB([]string{myConfig.LDB.CryptoTable, myConfig.LDB.PivotTable})
	if err == nil {
		t.Fatalf("LDB exists when it shouldn't have")
	}
	myConfig.LDB.LdbPath = ldbPath
	myConfig.LDB.Binary = ldbBinary
	err = ldbModel.PingLDB([]string{doesNotExist})
	if err == nil {
		t.Fatalf("LDB exists when it shouldn't have")
	}
}

func TestQueryPivotLDB_Pass(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = ldbPath
	myConfig.LDB.Binary = ldbBinary
	ldbModel := NewLdbModel(context.Background(), s, myConfig)

	urlHashesForTesting := []string{"7c110b4501c727f42f13fd616e2af522"}
	res, err := ldbModel.QueryBulkPivotLDB(urlHashesForTesting)
	if err != nil {
		t.Fatalf("Failed to query pivot table: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("No pivot table response data.")
	}
	fmt.Printf("Found pivot data: %v\n", res)
}

func TestQueryPivotLDB_Fail(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = doesNotExist
	myConfig.LDB.Binary = doesNotExist
	ldbModel := NewLdbModel(context.Background(), s, myConfig)

	urlHashesForTesting := []string{"7c110b4501c727f42f13fd616e2af522"}
	_, err = ldbModel.QueryBulkPivotLDB(urlHashesForTesting)
	if err == nil {
		t.Fatalf("Query should fail when it shouldn't have")
	}
}

func TestQueryCryptoLDB_Pass(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = ldbPath
	myConfig.LDB.Binary = ldbBinary
	ldbModel := NewLdbModel(context.Background(), s, myConfig)

	fileHashesForTesting := []string{"b9e4d7a54ff7267c285e266b5701de3a", "c0cc0cbd95f0f20cb95115b46e923482", "264a6f968bff7af75cd740eb6b646208"}
	var testItems = make(map[string][]string)
	testItems["7c110b4501c727f42f13fd616e2af522"] = fileHashesForTesting

	res, err := ldbModel.QueryBulkCryptoLDB(testItems)
	if err != nil {
		t.Fatalf("Failed to query crypto table: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("No crypto table response data.")
	}
	fmt.Printf("Found crypto data: %v\n", res)
}

func TestQueryCryptoLDB_Fail(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.LDB.Debug = true
	myConfig.LDB.LdbPath = doesNotExist
	myConfig.LDB.Binary = doesNotExist
	ldbModel := NewLdbModel(context.Background(), s, myConfig)

	fileHashesForTesting := []string{"b9e4d7a54ff7267c285e266b5701de3a", "c0cc0cbd95f0f20cb95115b46e923482", "264a6f968bff7af75cd740eb6b646208"}
	var testItems = make(map[string][]string)
	testItems["7c110b4501c727f42f13fd616e2af522"] = fileHashesForTesting
	_, err = ldbModel.QueryBulkCryptoLDB(testItems)
	if err == nil {
		t.Fatalf("Query should fail when it shouldn't have")
	}
}
