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
func NewCryptoUsageModel(ctx context.Context, s *zap.SugaredLogger, q *database.DBQueryContext) *CryptoUsageModel {
	return &CryptoUsageModel{ctx: ctx, s: s, q: q}
}

func (m *CryptoUsageModel) GetCryptoUsageByURLHash(urlHash string) ([]CryptoUsage, error) {
	if urlHash == "" {
		m.s.Errorf("Please specify a valid url_hash")
		return []CryptoUsage{}, errors.New("please specify a valid url hash to query")
	}
	stmt := "SELECT url_hash AS url_hash, algorithm_name, strength " +
		"FROM component_crypto c " +
		"WHERE url_hash = $1;"

	var usages []CryptoUsage
	err := m.q.SelectContext(m.ctx, &usages, stmt, urlHash)
	if err != nil {
		m.s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []CryptoUsage{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}

func (m *CryptoUsageModel) GetCryptoUsageByURLHashes(urlHashes []string) ([]CryptoUsage, error) {
	if len(urlHashes) == 0 {
		m.s.Infof("Please specify a valid Purl list to query")
		return []CryptoUsage{}, errors.New("please specify a valid Purl list to query")
	}
	var purlNames []string
	for p := range urlHashes {
		purlNames = append(purlNames, "'"+urlHashes[p]+"'")
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

/*
func (m *CryptoUsageModel) GetUsageByPurlMajor(purlname string, major string) ([]CryptoUsageOnVersion, error) {
	major = strings.ReplaceAll(major, "*", "%")
	stmt := "select au.purl_name as purl_name, au.version as version, cc.algorithm_name as algorithm_name,cc.strength as strength " +
		"from all_urls au,component_crypto cc " +
		"where cc.url_hash = au.package_hash and au.purl_name =$1 and au.version like $2;"
	fmt.Println(purlname, major)
	var usages []CryptoUsageOnVersion
	err := m.q.SelectContext(m.ctx, &usages, stmt, purlname, major)
	if err != nil {
		m.s.Errorf("Failed to query cryptoUsage:  %v", err)
		return []CryptoUsageOnVersion{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return usages, nil
}
*/
