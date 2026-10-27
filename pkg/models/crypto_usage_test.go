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
	"sort"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/testutils"
)

// The fixture's pkg:github/scanoss/engine, the component whose crypto rows the
// serving fixtures carry.
const (
	engineID      = "b5ccd188-eb1c-5476-bfc4-b6a44d5bacc4"
	engineVersion = "v5.4.7"
)

func setupCryptoModel(t *testing.T) (context.Context, *CryptoUsageModel, func()) {
	t.Helper()
	cleanupRulesets := testutils.SetupTestRulesetsDir(t)
	if err := zlog.NewSugaredDevLogger(); err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	db := sqliteSetup(t)
	if err := LoadTestSQLData(db, ctx); err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	return ctx, NewCryptoUsageModel(db), func() {
		CloseDB(db)
		zlog.SyncZap()
		cleanupRulesets()
	}
}

func TestGetCryptoUsageByPurlIDs(t *testing.T) {
	ctx, model, cleanup := setupCryptoModel(t)
	defer cleanup()
	s := ctxzap.Extract(ctx).Sugar()

	t.Run("known component version", func(t *testing.T) {
		usage, err := model.GetCryptoUsageByPurlIDs(ctx, s, []string{engineID}, []string{engineVersion})
		if err != nil {
			t.Fatalf("GetCryptoUsageByPurlIDs error = %v", err)
		}
		if len(usage) == 0 {
			t.Fatal("no crypto usage returned for a component the fixture carries")
		}
		got := make([]string, 0, len(usage))
		for _, u := range usage {
			// Every row must say which component version it belongs to, since that is
			// how the caller attributes algorithms back without mixing components up.
			if u.PurlID != engineID || u.Version != engineVersion {
				t.Errorf("row = (%s, %s), want (%s, %s)", u.PurlID, u.Version, engineID, engineVersion)
			}
			got = append(got, u.Algorithm)
		}
		sort.Strings(got)
		want := []string{"crc32", "des", "md5", "rsa"}
		if len(got) != len(want) {
			t.Fatalf("algorithms = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("algorithms = %v, want %v", got, want)
				break
			}
		}
	})

	// The algorithm name is crypto_algorithm.id, the short spelling the API
	// contract emits, not the long description the table also carries. Selecting
	// the wrong column is silent - both are non-empty strings - so it is asserted
	// here rather than left to the field.
	t.Run("strength is read from the catalogue", func(t *testing.T) {
		usage, err := model.GetCryptoUsageByPurlIDs(ctx, s, []string{engineID}, []string{engineVersion})
		if err != nil {
			t.Fatalf("GetCryptoUsageByPurlIDs error = %v", err)
		}
		byAlgorithm := make(map[string]string, len(usage))
		for _, u := range usage {
			byAlgorithm[u.Algorithm] = u.Strength
		}
		for algorithm, want := range map[string]string{"crc32": "32", "md5": "128", "des": "168", "rsa": "128"} {
			if got := byAlgorithm[algorithm]; got != want {
				t.Errorf("strength(%s) = %q, want %q", algorithm, got, want)
			}
		}
	})

	t.Run("unknown component or version returns nothing", func(t *testing.T) {
		for name, args := range map[string][2][]string{
			"unknown purl_id": {{"00000000-0000-0000-0000-000000000000"}, {engineVersion}},
			"unknown version": {{engineID}, {"99.99.99"}},
			"empty inputs":    {{"", ""}, {"", ""}},
			"no ids":          {nil, {engineVersion}},
		} {
			t.Run(name, func(t *testing.T) {
				usage, err := model.GetCryptoUsageByPurlIDs(ctx, s, args[0], args[1])
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(usage) != 0 {
					t.Errorf("got %d rows, want none", len(usage))
				}
			})
		}
	})
}

// A missing table is a query failure, not an empty result: a broken database must
// not be mistaken for a component with no cryptography.
func TestGetCryptoUsageByPurlIDsReportsQueryFailure(t *testing.T) {
	ctx, model, cleanup := setupCryptoModel(t)
	defer cleanup()
	s := ctxzap.Extract(ctx).Sugar()

	if err := RunTestSQL(model.db, ctx, "DROP TABLE component_version_crypto;"); err != nil {
		t.Fatalf("failed to drop the table: %v", err)
	}
	usage, err := model.GetCryptoUsageByPurlIDs(ctx, s, []string{engineID}, []string{engineVersion})
	if err == nil {
		t.Error("want an error once the table is gone")
	}
	if len(usage) != 0 {
		t.Errorf("got %d rows, want none", len(usage))
	}
}
