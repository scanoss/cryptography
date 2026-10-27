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

type CryptoUsageModel struct {
	db *sqlx.DB
}

// CryptoUsage is one algorithm detected in one version of one component.
//
// The mining schema keyed these rows by `url_hash`, the hash of a specific
// package archive, which the caller had to resolve through `all_urls` first.
// Serving keys them by (purl_id, version) directly, so the hash round-trip is
// gone and the version is carried on the row.
type CryptoUsage struct {
	PurlID    string `db:"purl_id"`
	Version   string `db:"version"`
	Algorithm string `db:"algorithm_name"`
	Strength  string `db:"strength"`
}

type CryptoUsageOnVersion struct {
	PurlName  string `db:"purl_name"`
	Version   string `db:"version"`
	Algorithm string `db:"algorithm_name"`
	Strength  string `db:"strength"`
}

type CryptoItem struct {
	Algorithm string
	Strength  string
}

// NewCryptoUsageModel creates a new instance of the Crypto Usage Model.
func NewCryptoUsageModel(db *sqlx.DB) *CryptoUsageModel {
	return &CryptoUsageModel{db}
}

// cryptoUsageQuery reads the algorithms detected in the given component versions.
//
// Both the name and the strength come from crypto_algorithm. `id` is the short name
// ("aes") the mining `component_crypto.algorithm_name` column held and the API
// contract emits; `name` is a long description ("Advanced Encryption Standard")
// this service does not expose.
//
// `strength` is read, not derived. An earlier revision derived it from the SPDX key
// sizes because the export carried no strength column; the export now carries one,
// and its 219 (algorithm, strength) pairs are identical to mining's. The SPDX
// derivation covered 118 of those 219 and disagreed where it did resolve - it makes
// aes "256" where mining, and this service, say "128-256".
const cryptoUsageQuery = `SELECT CAST(cvc.purl_id AS VARCHAR) AS purl_id,
	cvc.version              AS version,
	ca.id                    AS algorithm_name,
	COALESCE(ca.strength, '') AS strength
FROM component_version_crypto cvc
INNER JOIN crypto_algorithm ca ON ca.id = cvc.algorithm_id
WHERE cvc.purl_id IN (?) AND cvc.version IN (?)`

// GetCryptoUsageByPurlIDs returns the algorithms detected in the given versions
// of the given components.
//
// Both lists are applied as an IN filter, so a batch costs one query. The result
// carries purl_id and version on every row, letting the caller attribute each
// algorithm back to the exact component version that declared it - a component
// asking for one version never picks up another's rows.
func (m *CryptoUsageModel) GetCryptoUsageByPurlIDs(ctx context.Context, s *zap.SugaredLogger,
	purlIDs, versions []string,
) ([]CryptoUsage, error) {
	purlIDs, versions = nonEmpty(purlIDs), nonEmpty(versions)
	if len(purlIDs) == 0 || len(versions) == 0 {
		s.Debug("No component versions to query for crypto usage")
		return []CryptoUsage{}, nil
	}
	query, args, err := sqlx.In(cryptoUsageQuery, purlIDs, versions)
	if err != nil {
		s.Errorf("Failed to build the crypto usage query: %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to build the crypto usage query: %w", err)
	}
	var usages []CryptoUsage
	if err = m.db.SelectContext(ctx, &usages, m.db.Rebind(query), args...); err != nil {
		s.Errorf("Failed to query cryptoUsage: %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the component crypto table: %w", err)
	}
	if usages == nil {
		return []CryptoUsage{}, nil
	}
	return usages, nil
}

// nonEmpty drops empty strings from an IN-clause argument list, which would
// otherwise widen the filter for nothing.
func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
