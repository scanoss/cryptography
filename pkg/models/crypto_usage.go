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
	"errors"
	"fmt"
	"strings"

	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"
)

type CryptoUsageModel struct {
	ctx context.Context
	s   *zap.SugaredLogger
	q   *database.DBQueryContext
}

type CryptoUsage struct {
	URLHash   string `db:"url_hash"`
	Algorithm string `db:"algorithm_name"`
	Strength  string `db:"strength"`
}

type CryptoItem struct {
	Algorithm string
	Strength  string
}

// NewCryptoUsageModel creates a new instance of the Crypto Usage Model.
func NewCryptoUsageModel(ctx context.Context, s *zap.SugaredLogger, q *database.DBQueryContext) *CryptoUsageModel {
	return &CryptoUsageModel{ctx: ctx, s: s, q: q}
}

func (m *CryptoUsageModel) GetusageByUrlHash(url_hash string) ([]CryptoUsage, error) {
	if url_hash == "" {
		m.s.Errorf("Please specify a valid url_hash")
		return []CryptoUsage{}, errors.New("please specify a valid url hash to query")
	}
	stmt := "SELECT url_hash AS url_hash, algorithm_name, strength " +
		"FROM component_crypto c " +
		"WHERE url_hash = $1;"

	var usages []CryptoUsage
	err := m.q.SelectContext(m.ctx, &usages, stmt, url_hash)
	if err != nil {
		m.s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}

func (m *CryptoUsageModel) GetusageByUrlHashes(url_hashes []string) ([]CryptoUsage, error) {
	if len(url_hashes) == 0 {
		m.s.Errorf("Please specify a valid Purl list to query")
		return []CryptoUsage{}, errors.New("please specify a valid Purl list to query")
	}
	var purlNames []string
	for p := range url_hashes {
		purlNames = append(purlNames, "'"+url_hashes[p]+"'")
	}
	inStmt := strings.Join(purlNames, ",")
	inStmt = "(" + inStmt + ")"

	if inStmt == "()" {
		m.s.Errorf("No hashes to query")
		return []CryptoUsage{}, errors.New("no hashes to query")
	}
	stmt := "SELECT url_hash AS url_hash, algorithm_name, strength " +
		"FROM component_crypto c " +
		"WHERE url_hash in " + inStmt

	var usages []CryptoUsage
	err := m.q.SelectContext(m.ctx, &usages, stmt)
	if err != nil {
		m.s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}
