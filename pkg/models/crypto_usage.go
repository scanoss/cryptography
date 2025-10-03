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
	_ "context"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"strings"
)

type CryptoUsageModel struct {
	db *sqlx.DB
}

type CryptoUsage struct {
	URLHash   string `db:"url_hash"`
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

func (m *CryptoUsageModel) GetCryptoUsageByURLHashes(ctx context.Context, s *zap.SugaredLogger, urlHashes []string) ([]CryptoUsage, error) {
	if len(urlHashes) == 0 {
		s.Infof("Please specify a valid Purl list to query")
		return []CryptoUsage{}, errors.New("please specify a valid Purl list to query")
	}
	var purlNames []string
	for p := range urlHashes {
		purlNames = append(purlNames, "'"+urlHashes[p]+"'")
	}
	inStmt := strings.Join(purlNames, ",")
	inStmt = "(" + inStmt + ")"

	if inStmt == "()" {
		s.Errorf("No hashes to query")
		return []CryptoUsage{}, errors.New("no hashes to query")
	}
	stmt := "SELECT url_hash AS url_hash, algorithm_name, strength " +
		"FROM component_crypto c " +
		"WHERE url_hash in " + inStmt
	var usages []CryptoUsage
	err := m.db.SelectContext(ctx, &usages, stmt)
	if err != nil {
		s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}
