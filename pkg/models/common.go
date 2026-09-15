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

// This file common tasks for the models package

package models

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

// loadSQLData Load the specified SQL files into the supplied DB.
func loadSQLData(db *sqlx.DB, ctx context.Context, filename string) error {
	fmt.Printf("Loading test data file: %v\n", filename)
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if db != nil {
		_, err = db.ExecContext(ctx, string(file))
	}
	if err != nil {
		return err
	}
	return nil
}

// testDataFiles are the data fixtures loaded on top of the schema. They carry data
// only; the tables come from testSchemaDDL in test_schema.go. Paths are relative to
// a package directory under pkg/.
var testDataFiles = []string{
	"../models/tests/component.sql",
	"../models/tests/component_version.sql",
	"../models/tests/crypto_algorithm.sql",
	"../models/tests/component_version_crypto.sql",
	"../models/tests/crypto_library.sql",
	"../models/tests/component_version_crypto_library.sql",
}

// idempotentDDL rewrites CREATE TABLE/INDEX into their IF NOT EXISTS form so a test
// can load the schema more than once. testSchemaDDL transcribes production and must
// not carry test-only clauses, so the rewrite happens here instead of in the constant.
func idempotentDDL(sql string) string {
	for _, kind := range []string{"TABLE", "INDEX"} {
		bare := "CREATE " + kind + " "
		guarded := bare + "IF NOT EXISTS "
		// Normalise first, so an already-guarded statement is not double-guarded.
		sql = strings.ReplaceAll(sql, guarded, bare)
		sql = strings.ReplaceAll(sql, bare, guarded)
	}
	return sql
}

// LoadTestSchema creates the serving schema in the supplied DB. Call this before
// loading any data fixture, since the fixtures do not define their own tables.
// It is safe to call more than once on the same DB.
func LoadTestSchema(db *sqlx.DB, ctx context.Context) error {
	if err := runSQL(db, ctx, idempotentDDL(testSchemaDDL)); err != nil {
		return fmt.Errorf("failed to load the test schema: %w", err)
	}
	return nil
}

// LoadTestSQLData loads the serving schema plus all the test data fixtures.
func LoadTestSQLData(db *sqlx.DB, ctx context.Context) error {
	// In-memory SQLite gives each pooled connection its OWN empty database. Version
	// resolution runs concurrently (worker pool), so multiple connections would race
	// and some queries would hit a connection without the loaded fixtures ("no such
	// table"). Pin the pool to a single connection so every query sees the same
	// in-memory database.
	db.SetMaxOpenConns(1)
	if err := LoadTestSchema(db, ctx); err != nil {
		return err
	}
	return loadTestSQLDataFiles(db, ctx, testDataFiles)
}

func RunTestSQL(db *sqlx.DB, ctx context.Context, stm string) error {
	return runSQL(db, ctx, stm)
}

func runSQL(db *sqlx.DB, ctx context.Context, stm string) error {
	fmt.Printf("Running %+v\n", stm)
	var err error
	if db != nil {
		_, err = db.ExecContext(ctx, stm)
	}
	if err != nil {
		return err
	}
	return nil
}

// loadTestSQLDataFiles loads a list of test SQL files.
func loadTestSQLDataFiles(db *sqlx.DB, ctx context.Context, files []string) error {
	for _, file := range files {
		err := loadSQLData(db, ctx, file)
		if err != nil {
			return err
		}
	}
	return nil
}

// sqliteSetup sets up an in-memory SQL Lite DB for testing.
func sqliteSetup(t *testing.T) *sqlx.DB {
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	return db
}

// CloseDB closes the specified DB and logs any errors.
func CloseDB(db *sqlx.DB) {
	if db != nil {
		err := db.Close()
		if err != nil {
			zlog.S.Warnf("Problem closing DB: %v", err)
		}
	}
}

// CloseConn closes the specified DB connection and logs any errors.
func CloseConn(conn *sqlx.Conn) {
	if conn != nil {
		err := conn.Close()
		if err != nil {
			zlog.S.Warnf("Problem closing DB connection: %v", err)
		}
	}
}
