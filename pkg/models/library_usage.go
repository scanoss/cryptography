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

type ECUsageModel struct {
	ctx context.Context
	s   *zap.SugaredLogger
	q   *database.DBQueryContext
}

type ECUsage struct {
	URLHash     string `db:"url_hash"`
	Id          string `db:"id"`
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
	Id          string
	Name        string
	Description string
	URL         string
	Purl        string
	Category    string
}

// NewCryptoUsageModel creates a new instance of the Crypto Usage Model.
func NewECUsageModel(ctx context.Context, s *zap.SugaredLogger, q *database.DBQueryContext) *ECUsageModel {
	return &ECUsageModel{ctx: ctx, s: s, q: q}
}

func (m *ECUsageModel) GetLibraryUsageByURLHashes(urlHashes []string) ([]ECUsage, error) {
	if len(urlHashes) == 0 {
		m.s.Errorf("Please specify a valid Purl list to query")
		return []ECUsage{}, errors.New("please specify a valid Purl list to query")
	}
	var purlNames []string
	for p := range urlHashes {
		if urlHashes[p] != "" {
			purlNames = append(purlNames, "'"+urlHashes[p]+"'")
		}
	}
	inStmt := strings.Join(purlNames, ",")
	inStmt = "(" + inStmt + ")"

	if inStmt == "()" {
		m.s.Errorf("No hashes to query")
		return []ECUsage{}, errors.New("no hashes to query")
	}
	stmt := "SELECT url_hash AS url_hash, det_id as id ,name,description, url, category, purl " +
		"FROM crypto_libraries ec, component_crypto_library cc " +
		"WHERE url_hash in " + inStmt + " and cc.det_id=ec.id;"
	fmt.Println(stmt)
	var usages []ECUsage
	err := m.q.SelectContext(m.ctx, &usages, stmt)
	if err != nil {
		m.s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []ECUsage{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}
