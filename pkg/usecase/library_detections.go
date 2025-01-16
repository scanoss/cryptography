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

package usecase

import (
	"context"
	"errors"
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

type ECDetectionUseCase struct {
	ctx     context.Context
	s       *zap.SugaredLogger
	conn    *sqlx.Conn
	allUrls *models.AllUrlsModel
	usage   *models.ECUsageModel
}

func NewECDetection(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *ECDetectionUseCase {
	return &ECDetectionUseCase{ctx: ctx, s: s, conn: conn,
		allUrls: models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		usage:   models.NewECUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetCrypto takes the Crypto Input request, searches for Cryptographic usages and returns a CrytoOutput struct.
func (d ECDetectionUseCase) GetDetectionsInRange(request dtos.CryptoInput) (dtos.ECOutput, models.QuerySummary, error) {
	if len(request.Purls) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.ECOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}
	out := dtos.ECOutput{}
	summary := models.QuerySummary{}
	// Prepare purls to query
	for _, reqPurl := range request.Purls {
		purl, err := purlhelper.PurlFromString(reqPurl.Purl)
		if err != nil {
			//	d.s.Logf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue
		}
		if reqPurl.Requirement == "*" || strings.HasPrefix(reqPurl.Requirement, "v*") {
			return dtos.ECOutput{}, models.QuerySummary{}, errors.New("requirement should include version range or major and wildcard")
		}
		purlName, err := purlhelper.PurlNameFromString(reqPurl.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)

			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameTypeInRange(purlName, purl.Type, reqPurl.Requirement)
		if errQ != nil {
			//	d.s.Errorf("Missing requirement for purl '%s': %s", reqPurl.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue

		}
		if len(res) == 0 {
			summary.PurlsNotFound = append(summary.PurlsNotFound, purlName)
			continue
		}
		_ = errQ
		item := dtos.ECOutputItem{Purl: reqPurl.Purl, Versions: []string{}}
		hashes := []string{}
		nonDupVersions := make(map[string]bool)
		mapVersionHash := make(map[string]string)
		for _, url := range res {
			if url.URLHash == "" {
				// No information for this url
			} else {
				hashes = append(hashes, url.URLHash)
				mapVersionHash[url.URLHash] = url.SemVer
			}
		}
		uses, err1 := d.usage.GetLibraryUsageByURLHashes(hashes)
		if err1 != nil {
			d.s.Errorf("error getting algorithms usage for purl '%s': %s", reqPurl.Purl, err)
		}
		// avoid duplicate detections (if any)
		// Duplicates should have been removed on mining but some appended keyword may produce a duplicate entry for an existing url
		nonDupAlgorithms := make(map[string]bool)
		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[alg.Id]; !exist {
				nonDupAlgorithms[alg.Id] = true
				item.Detections = append(item.Detections,
					dtos.ECDetectedItem{Id: alg.Id,
						Name:        alg.Name,
						Description: alg.Description,
						URL:         alg.URL,
						Categoty:    alg.Category,
						Purl:        alg.Purl})
			}
		}
		item.Versions = []string{}
		for k, _ := range nonDupVersions {
			item.Versions = append(item.Versions, k)
		}

		sort.Slice(item.Versions, func(i, j int) bool {
			versionA, _ := semver.NewVersion(item.Versions[i])
			versionB, _ := semver.NewVersion(item.Versions[j])

			return versionA.LessThan(versionB)
		})

		if len(uses) == 0 {
			summary.PurlsWOInfo = append(summary.PurlsWOInfo, reqPurl.Purl)
		}

		out.Hints = append(out.Hints, item)

	}
	return out, summary, nil
}
