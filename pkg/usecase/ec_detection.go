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
	"strings"

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
func (d ECDetectionUseCase) GetDetectionsInRange(request dtos.CryptoInput) (dtos.ECOutput, int, error) {
	notFound := 0
	if len(request.Purls) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.ECOutput{}, 0, errors.New("empty list of purls")
	}
	out := dtos.ECOutput{}

	// Prepare purls to query
	for _, reqPurl := range request.Purls {
		purl, err := purlhelper.PurlFromString(reqPurl.Purl)
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			notFound++
			continue
		}
		if reqPurl.Requirement == "*" || strings.HasPrefix(reqPurl.Requirement, "v*") {
			return dtos.ECOutput{}, 0, errors.New("requirement should include version range or major and wildcard")
		}
		purlName, err := purlhelper.PurlNameFromString(reqPurl.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			notFound++
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameTypeInRange(purlName, purl.Type, reqPurl.Requirement)
		if len(res) == 0 {
			notFound++
			continue
		}
		_ = errQ
		item := dtos.ECOutputItem{Purl: reqPurl.Purl, Versions: []string{}}
		hashes := []string{}
		nonDupVersions := make(map[string]bool)
		for _, url := range res {
			hashes = append(hashes, url.URLHash)
			// avoid duplicate versions
			if _, exist := nonDupVersions[url.SemVer]; !exist {
				nonDupVersions[url.SemVer] = true
				item.Versions = append(item.Versions, url.SemVer)

			}
		}
		uses, err1 := d.usage.GetECUsageByURLHashes(hashes)
		if err1 != nil {
			d.s.Errorf("error getting algorithms usage for purl '%s': %s", reqPurl.Purl, err)
		}
		// avoid duplicate algorithms
		nonDupAlgorithms := make(map[string]bool)
		for _, alg := range uses {

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

		out.Hints = append(out.Hints, item)

	}
	return out, notFound, nil
}
