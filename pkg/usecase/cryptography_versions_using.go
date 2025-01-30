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

package usecase

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"

	"github.com/jmoiron/sqlx"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type VersionsUsingCrypto struct {
	ctx         context.Context
	s           *zap.SugaredLogger
	conn        *sqlx.Conn
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewVersionsUsingCrypto(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *VersionsUsingCrypto {
	return &VersionsUsingCrypto{ctx: ctx, s: s, conn: conn,
		allUrls:     models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		cryptoUsage: models.NewCryptoUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetVersionsUsingCryptoInRange takes the Crypto Input request, searches for Cryptographic and return versions that uses and does not use crypto.
func (d VersionsUsingCrypto) GetVersionsInRangeUsingCrypto(request dtos.CryptoInput) (dtos.VersionsInRangeOutput, models.QuerySummary, error) {

	if len(request.Purls) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.VersionsInRangeOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}
	out := dtos.VersionsInRangeOutput{}
	summary := models.QuerySummary{}
	// Prepare purls to query
	for _, reqPurl := range request.Purls {
		purl, err := purlhelper.PurlFromString(reqPurl.Purl)
		if err != nil {

			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue
		}
		if reqPurl.Requirement == "*" || strings.HasPrefix(reqPurl.Requirement, "v*") {
			return dtos.VersionsInRangeOutput{}, models.QuerySummary{}, errors.New("requirement should include version range or major and wildcard")
		}
		purlName, err := purlhelper.PurlNameFromString(reqPurl.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {

			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameTypeInRange(purlName, purl.Type, reqPurl.Requirement)
		if len(res) == 0 {
			summary.PurlsNotFound = append(summary.PurlsNotFound, purlName)
			continue
		}

		_ = errQ
		item := dtos.VersionsInRangeUsingCryptoItem{Purl: reqPurl.Purl, VersionsWith: []string{}, VersionsWithout: []string{}}
		hashes := []string{}
		nonDupVersions := make(map[string]bool)
		//allVersions := []string{}
		mapVersionHash := make(map[string]string)
		for _, url := range res {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
			nonDupVersions[url.SemVer] = false
		}
		uses, err1 := d.cryptoUsage.GetCryptoUsageByURLHashes(hashes)
		if err1 != nil {
			d.s.Infof("error getting algorithms usage for purl '%s': %s", reqPurl.Purl, err)
		}

		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
		}
		for k, v := range nonDupVersions {
			if v {
				item.VersionsWith = append(item.VersionsWith, k)
			} else {
				item.VersionsWithout = append(item.VersionsWithout, k)
			}
		}
		sort.Strings(item.VersionsWith)
		sort.Strings(item.VersionsWithout)

		if len(uses) == 0 {
			summary.PurlsWOInfo = append(summary.PurlsWOInfo, reqPurl.Purl)
		}

		out.Versions = append(out.Versions, item)

	}
	return out, summary, nil
}
