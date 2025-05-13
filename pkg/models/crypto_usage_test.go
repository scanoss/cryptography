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
	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	myconfig "scanoss.com/cryptography/pkg/config"
)

func TestCryptoSearchUsageByList(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db := sqliteSetup(t) // Setup SQL Lite DB
	defer CloseDB(db)
	conn := sqliteConn(t, ctx, db) // Get a connection from the pool
	defer CloseConn(conn)
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Database.Trace = true

	cum := NewCryptoUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, myConfig.Database.Trace))

	usage, err := cum.GetCryptoUsageByURLHashes([]string{"7774ed78584b719f076bb92aa42fbc7f", "541bae26cbf8e2d2f33d20cd22d435dd"})
	if err != nil {
		t.Errorf("GetCryptoUsageByURLHashes error = %v", err)
	}
	if len(usage) == 0 {
		t.Errorf("GetCryptoUsageByURLHashes No URLs returned from query")
	}
	fmt.Printf("All Urls Version: %#v\n", usage)
	usage, err = cum.GetCryptoUsageByURLHashes([]string{"7774e978584b719f076bb92aa42fbc7f", "541bae267bf8e2d2f33d20cd22d435dd"})
	if err != nil {
		t.Errorf("GetCryptoUsageByURLHashes error = %v", err)
	}
	if len(usage) != 0 {
		t.Errorf("GetCryptoUsageByURLHashes No URLs returned from query")
	}

	usage, err = cum.GetCryptoUsageByURLHashes([]string{"", ""})
	if err != nil {
		t.Errorf("GetCryptoUsageByURLHashes error = %v", err)
	}
	if len(usage) != 0 {
		t.Errorf("GetCryptoUsageByURLHashes No URLs returned from query")
	}

	_ = RunTestSQL(db, ctx, conn, "DROP TABLE component_crypto;")
	usage, err = cum.GetCryptoUsageByURLHashes([]string{"7774e978584b719f076bb92aa42fbc7f", "541bae267bf8e2d2f33d20cd22d435dd"})
	if err == nil {
		t.Errorf("Expected to get an error on GetCryptoUsageByURLHashes ")
	}
	if len(usage) != 0 {
		t.Errorf("GetCryptoUsageByURLHashes No URLs returned from query")
	}
}
