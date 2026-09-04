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
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/testutils"
)

// The fixture's pkg:github/pineappleea/pineapple-src, the component whose
// crypto-library detections the serving fixtures carry.
const (
	pineappleID      = "018327fd-8993-5c93-a7eb-3320b845a4d5"
	pineappleVersion = "v5.4.7"
)

func setupECModel(t *testing.T) (context.Context, *ECUsageModel, func()) {
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
	return ctx, NewECUsageModel(db), func() {
		CloseDB(db)
		zlog.SyncZap()
		cleanupRulesets()
	}
}

func TestGetLibraryUsageByPurlIDs(t *testing.T) {
	ctx, model, cleanup := setupECModel(t)
	defer cleanup()
	s := ctxzap.Extract(ctx).Sugar()

	t.Run("known component version", func(t *testing.T) {
		usage, err := model.GetLibraryUsageByPurlIDs(ctx, s, []string{pineappleID}, []string{pineappleVersion})
		if err != nil {
			t.Fatalf("GetLibraryUsageByPurlIDs error = %v", err)
		}
		if len(usage) == 0 {
			t.Fatal("no library detections returned for a component the fixture carries")
		}
		for _, u := range usage {
			if u.PurlID != pineappleID || u.Version != pineappleVersion {
				t.Errorf("row = (%s, %s), want (%s, %s)", u.PurlID, u.Version, pineappleID, pineappleVersion)
			}
			if u.ID == "" {
				t.Error("detection has no library id")
			}
		}
	})

	t.Run("library metadata is joined in", func(t *testing.T) {
		usage, err := model.GetLibraryUsageByPurlIDs(ctx, s, []string{pineappleID}, []string{pineappleVersion})
		if err != nil {
			t.Fatalf("GetLibraryUsageByPurlIDs error = %v", err)
		}
		var found bool
		for _, u := range usage {
			if u.ID != "library/boringssl" {
				continue
			}
			found = true
			if u.Name == "" || u.Category == "" || u.Description == "" {
				t.Errorf("library/boringssl came back without its metadata: %+v", u)
			}
		}
		if !found {
			t.Error("library/boringssl not among the detections")
		}
	})

	// The join is inner: a detection naming a library the catalogue does not carry
	// is dropped rather than surfacing with empty metadata. The mining query behaved
	// the same way, and the fixture keeps such a dangling reference to pin it.
	t.Run("detections without a catalogue entry are dropped", func(t *testing.T) {
		usage, err := model.GetLibraryUsageByPurlIDs(ctx, s, []string{pineappleID}, []string{pineappleVersion})
		if err != nil {
			t.Fatalf("GetLibraryUsageByPurlIDs error = %v", err)
		}
		for _, u := range usage {
			if u.ID == "library/openssl" {
				t.Error("library/openssl has no crypto_library row; it should not be returned")
			}
		}
	})

	t.Run("unknown component or version returns nothing", func(t *testing.T) {
		for name, args := range map[string][2][]string{
			"unknown purl_id": {{"00000000-0000-0000-0000-000000000000"}, {pineappleVersion}},
			"unknown version": {{pineappleID}, {"99.99.99"}},
			"empty inputs":    {{""}, {""}},
		} {
			t.Run(name, func(t *testing.T) {
				usage, err := model.GetLibraryUsageByPurlIDs(ctx, s, args[0], args[1])
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

// A missing table is a query failure, not an empty result.
func TestGetLibraryUsageByPurlIDsReportsQueryFailure(t *testing.T) {
	ctx, model, cleanup := setupECModel(t)
	defer cleanup()
	s := ctxzap.Extract(ctx).Sugar()

	if err := RunTestSQL(model.db, ctx, "DROP TABLE component_version_crypto_library;"); err != nil {
		t.Fatalf("failed to drop the table: %v", err)
	}
	usage, err := model.GetLibraryUsageByPurlIDs(ctx, s, []string{pineappleID}, []string{pineappleVersion})
	if err == nil {
		t.Error("want an error once the table is gone")
	}
	if len(usage) != 0 {
		t.Errorf("got %d rows, want none", len(usage))
	}
}
