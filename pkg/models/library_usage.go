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

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

type ECUsageModel struct {
	db *sqlx.DB
}

// ECUsage is one crypto-library hint detected in one version of one component.
// Keyed by (purl_id, version) in serving, where mining keyed it by url_hash.
type ECUsage struct {
	PurlID      string `db:"purl_id"`
	Version     string `db:"version"`
	ID          string `db:"id"`
	Name        string `db:"name"`
	Description string `db:"description"`
	URL         string `db:"url"`
	Purl        string `db:"purl"`
	Category    string `db:"category"`
}

type ECUsageOnVersion struct {
	PurlName  string `db:"purl_name"`
	Version   string `db:"version"`
	Algorithm string `db:"algorithm_name"`
	Strength  string `db:"strength"`
}

type ECDetectionItem struct {
	ID          string
	Name        string
	Description string
	URL         string
	Purl        string
	Category    string
}

// NewECUsageModel creates a new instance of the Crypto Usage Model.
func NewECUsageModel(db *sqlx.DB) *ECUsageModel {
	return &ECUsageModel{db: db}
}

// libraryUsageQuery reads the crypto-library hints detected in the given
// component versions. The mining query joined `crypto_libraries` to
// `component_crypto_library` on a detection id and filtered by url_hash; serving
// names the tables `crypto_library` / `component_version_crypto_library` and keys
// them by (purl_id, version).
const libraryUsageQuery = `SELECT CAST(cvcl.purl_id AS VARCHAR) AS purl_id,
	cvcl.version                  AS version,
	cl.id                         AS id,
	COALESCE(cl.name, '')         AS name,
	COALESCE(cl.description, '')  AS description,
	COALESCE(cl.url, '')          AS url,
	COALESCE(cl.purl, '')         AS purl,
	COALESCE(cl.category, '')     AS category
FROM component_version_crypto_library cvcl
INNER JOIN crypto_library cl ON cl.id = cvcl.library_id
WHERE cvcl.purl_id IN (?) AND cvcl.version IN (?)`

// GetLibraryUsageByPurlIDs returns the crypto-library hints detected in the given
// versions of the given components, one query per batch.
func (m *ECUsageModel) GetLibraryUsageByPurlIDs(ctx context.Context, s *zap.SugaredLogger,
	purlIDs, versions []string,
) ([]ECUsage, error) {
	purlIDs, versions = nonEmpty(purlIDs), nonEmpty(versions)
	if len(purlIDs) == 0 || len(versions) == 0 {
		s.Debug("No component versions to query for library usage")
		return []ECUsage{}, nil
	}
	query, args, err := sqlx.In(libraryUsageQuery, purlIDs, versions)
	if err != nil {
		s.Errorf("Failed to build the library usage query: %v", err)
		return []ECUsage{}, fmt.Errorf("failed to build the library usage query: %w", err)
	}
	var usages []ECUsage
	if err = m.db.SelectContext(ctx, &usages, m.db.Rebind(query), args...); err != nil {
		s.Errorf("Failed to query library usage: %v", err)
		return []ECUsage{}, fmt.Errorf("failed to query the component crypto library table: %w", err)
	}
	return usages, nil
}
