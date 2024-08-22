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
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoUseCase struct {
	ctx         context.Context
	s           *zap.SugaredLogger
	conn        *sqlx.Conn
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}
type CryptoWorkerStruct struct {
	URLMd5  string
	Purl    string
	Version string
}
type InternalQuery struct {
	CompletePurl    string
	PurlName        string
	Requirement     string
	SelectedVersion string
	SelectedURLS    []models.AllURL
}

func NewCrypto(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *CryptoUseCase {
	return &CryptoUseCase{ctx: ctx, s: s, conn: conn,
		allUrls:     models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		cryptoUsage: models.NewCryptoUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetCrypto takes the Crypto Input request, searches for Cryptographic usages and returns a CrytoOutput struct.
func (d CryptoUseCase) GetCrypto(request dtos.CryptoInput) (dtos.CryptoOutput, int, error) {
	notFound := 0
	if len(request.Purls) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.CryptoOutput{}, 0, errors.New("empty list of purls")
	}
	var query []InternalQuery
	var purlsToQuery []utils.PurlReq // Purls to search the database for
	// Prepare purls to query
	for _, reqPurl := range request.Purls {
		purl, err := purlhelper.PurlFromString(reqPurl.Purl)
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			notFound++
			continue
		}
		purlName, err := purlhelper.PurlNameFromString(reqPurl.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			notFound++
			continue
		}
		purlReq := reqPurl.Requirement
		if len(purlReq) > 0 && strings.HasPrefix(purlReq, "file:") { // internal dependency requirement. Assume latest
			d.s.Debugf("Removing 'local' requirement for purl: %v (req: %v)", reqPurl.Purl, purlReq)
			purlReq = ""
		}
		if len(purl.Version) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
			ver := purlhelper.GetVersionFromReq(purlReq)
			if len(ver) > 0 {
				purl.Version = ver // Switch to exact version search (faster)
			}
		}
		d.s.Debugf("Purl to query: %v, Name: %s, Version: %s", purl, purlName, purl.Version)

		purlsToQuery = append(purlsToQuery, utils.PurlReq{Purl: purlName, Version: purl.Version})
		query = append(query, InternalQuery{CompletePurl: reqPurl.Purl, Requirement: purl.Version, PurlName: purlName})
	}
	urls, err := d.allUrls.GetUrlsByPurlList(purlsToQuery)
	if err != nil {
		d.s.Warnf("Failed to get list of urls from (%v): %s", purlsToQuery, err)
	}
	if len(urls) == 0 {
		return dtos.CryptoOutput{}, len(request.Purls), nil
	}

	purlMap := make(map[string][]models.AllURL)
	///Order Urls in a map for fast access by purlname
	for r := range urls {
		purlMap[urls[r].PurlName] = append(purlMap[urls[r].PurlName], urls[r])
	}
	var urlHashes []string
	// For all the requested purls, choose the closest urls that matches the version. If not found, pick the latest one
	for r := range query {
		query[r].SelectedURLS, err = models.PickClosestUrls(d.s, purlMap[query[r].PurlName], query[r].PurlName, "", query[r].Requirement)
		if err != nil {
			return dtos.CryptoOutput{}, 0, err
		}
		if len(query[r].SelectedURLS) > 0 {
			query[r].SelectedVersion = query[r].SelectedURLS[0].Version
			for h := range query[r].SelectedURLS {
				urlHashes = append(urlHashes, query[r].SelectedURLS[h].URLHash)
			}
		} else {
			// NO URL linked to that reqPurl
			notFound++
		}
	}

	usage, errGetURL := d.cryptoUsage.GetUsageByURLHashes(urlHashes)
	if errGetURL != nil {
		return dtos.CryptoOutput{}, 0, errors.New("error retrieving url hashes")
	}
	mapCrypto := make(map[string][]models.CryptoItem)

	// group algorithms for a urlhash
	for _, v := range usage {
		mapCrypto[v.URLHash] = append(mapCrypto[v.URLHash], models.CryptoItem{Algorithm: v.Algorithm, Strength: v.Strength})
	}

	retV := dtos.CryptoOutput{}
	// Create the response
	for r := range query {
		var cryptoOutItem dtos.CryptoOutputItem
		algorithms := make(map[string]bool)
		relatedURLs := query[r].SelectedURLS
		cryptoOutItem.Version = query[r].SelectedVersion
		cryptoOutItem.Purl = query[r].CompletePurl
		for u := range relatedURLs {
			hash := relatedURLs[u].URLHash
			items := mapCrypto[hash]
			// remove duplicates for the same URL (if any)
			for i := range items {
				if _, exist := algorithms[strings.ToLower(items[i].Algorithm)]; !exist {
					cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: strings.ToLower(items[i].Algorithm), Strength: items[i].Strength})
					algorithms[strings.ToLower(items[i].Algorithm)] = true
				}
			}
		}
		retV.Cryptography = append(retV.Cryptography, cryptoOutItem)
	}
	return retV, notFound, nil
}
