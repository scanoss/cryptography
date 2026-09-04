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
	"database/sql"
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
// Strength is not stored: the mining schema had a `strength` column on
// component_crypto, and serving does not. It is derived instead from the SPDX key
// sizes, the same way the current decoration service derives it. The join is LEFT
// because not every algorithm has an SPDX entry with key sizes.
const cryptoUsageQuery = `SELECT CAST(cvc.purl_id AS VARCHAR) AS purl_id,
	cvc.version AS version,
	ca.name     AS algorithm_name,
	sca."commonkeySize"        AS common_key_size,
	sca."specifiedkeySize_max" AS max_key_size
FROM component_version_crypto cvc
INNER JOIN crypto_algorithm ca ON ca.id = cvc.algorithm_id
LEFT JOIN "SPDX_crypto_algorithm" sca ON sca.id = cvc.algorithm_id
WHERE cvc.purl_id IN (?) AND cvc.version IN (?)`

// cryptoUsageRow is cryptoUsageQuery's projection, before the key sizes are
// folded into a strength string.
type cryptoUsageRow struct {
	PurlID        string         `db:"purl_id"`
	Version       string         `db:"version"`
	Algorithm     string         `db:"algorithm_name"`
	CommonKeySize sql.NullString `db:"common_key_size"`
	MaxKeySize    sql.NullString `db:"max_key_size"`
}

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
	var rows []cryptoUsageRow
	if err = m.db.SelectContext(ctx, &rows, m.db.Rebind(query), args...); err != nil {
		s.Errorf("Failed to query cryptoUsage: %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the component crypto table: %w", err)
	}
	usages := make([]CryptoUsage, 0, len(rows))
	for _, r := range rows {
		usages = append(usages, CryptoUsage{
			PurlID:    r.PurlID,
			Version:   r.Version,
			Algorithm: r.Algorithm,
			Strength:  StrengthFromKeySizes(r.CommonKeySize, r.MaxKeySize),
		})
	}
	return usages, nil
}

// StrengthFromKeySizes builds the strength string from the SPDX key sizes: empty
// when neither is set, the single value when only one is or both agree, and
// "common-max" otherwise.
//
// This reproduces what the current decoration service emits, which is not always
// what the mining `strength` column held: of the algorithms present in both, 90
// agree and 35 do not, and a handful read oddly because SPDX records a maximum
// below the common size (des becomes "168-56"). Matching the decoration service
// was the deliberate choice, so the two report the same thing.
func StrengthFromKeySizes(common, max sql.NullString) string {
	c, m := "", ""
	if common.Valid {
		c = common.String
	}
	if max.Valid {
		m = max.String
	}
	switch {
	case c == "" && m == "":
		return ""
	case c == "":
		return m
	case m == "" || m == c:
		return c
	default:
		return c + "-" + m
	}
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
