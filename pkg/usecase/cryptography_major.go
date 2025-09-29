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
	"fmt"
	"scanoss.com/cryptography/pkg/utils"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"

	"github.com/jmoiron/sqlx"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type CryptoMajorUseCase struct {
	ctx         context.Context
	s           *zap.SugaredLogger
	conn        *sqlx.Conn
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewCryptoMajor(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *CryptoMajorUseCase {
	return &CryptoMajorUseCase{ctx: ctx, s: s, conn: conn,
		allUrls:     models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		cryptoUsage: models.NewCryptoUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetCryptoInRange takes the Crypto Input request, searches for Cryptographic usages and returns a CryptoOutput struct.
func (d CryptoMajorUseCase) GetCryptoInRange(components []dtos.ComponentDTO) (dtos.CryptoInRangeOutput, models.QuerySummary, error) {
	if len(components) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.CryptoInRangeOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}
	out := dtos.CryptoInRangeOutput{}
	summary := models.QuerySummary{}
	summary.TotalPurls = len(components)
	// Prepare purls to query
	for _, c := range components {
		purl, err := purlhelper.PurlFromString(c.Purl)
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", c.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			continue
		}
		if c.Requirement == "*" || strings.HasPrefix(c.Requirement, "v*") {
			return dtos.CryptoInRangeOutput{}, models.QuerySummary{}, errors.New("requirement should include version range or major and wildcard")
		}

		if c.Requirement != "" {
			if !utils.IsValidRequirement(c.Requirement) {
				summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, fmt.Sprintf("purl: %s , requirement: %s", c.Purl, c.Requirement))
				continue
			}
		}

		purlName, err := purlhelper.PurlNameFromString(c.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", c.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameTypeInRange(purlName, purl.Type, c.Requirement, &summary)
		if len(res) == 0 {
			summary.PurlsNotFound = append(summary.PurlsNotFound, purlName)
			continue
		}
		_ = errQ
		item := dtos.CryptoInRangeOutputItem{Purl: c.Purl, Versions: []string{}}
		var hashes []string
		nonDupVersions := make(map[string]bool)

		mapVersionHash := make(map[string]string)
		for _, url := range res {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
		}
		uses, err1 := d.cryptoUsage.GetCryptoUsageByURLHashes(hashes)
		if err1 != nil {
			d.s.Errorf("error getting algorithms usage for purl '%s': %s", c.Purl, err)
		}
		// avoid duplicate algorithms
		fmt.Printf("USES %v", uses)
		nonDupAlgorithms := make(map[models.CryptoItem]bool)
		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}]; !exist {
				nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}] = true
				item.Algorithms = append(item.Algorithms, dtos.CryptoUsageItem{Algorithm: alg.Algorithm, Strength: alg.Strength})
			}
		}
		for k := range nonDupVersions {
			item.Versions = append(item.Versions, k)
		}

		sort.Slice(item.Versions, func(i, j int) bool {
			versionA, _ := semver.NewVersion(item.Versions[i])
			versionB, _ := semver.NewVersion(item.Versions[j])

			return versionA.LessThan(versionB)
		})

		if len(uses) == 0 {
			summary.PurlsWOInfo = append(summary.PurlsWOInfo, c.Purl)
		}

		out.Cryptography = append(out.Cryptography, item)
	}
	return out, summary, nil
}
