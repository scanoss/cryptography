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
	"strings"

	"github.com/jmoiron/sqlx"
	"scanoss.com/cryptography/pkg/dtos"
	zlog "scanoss.com/cryptography/pkg/logger"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoUseCase struct {
	ctx     context.Context
	conn    *sqlx.Conn
	allUrls *models.AllUrlsModel
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
	SelectedURLS    []models.AllUrl
}

func NewCrypto(ctx context.Context, conn *sqlx.Conn) *CryptoUseCase {
	return &CryptoUseCase{ctx: ctx, conn: conn,
		allUrls: models.NewAllUrlModel(ctx, conn, models.NewProjectModel(ctx, conn)),
	}
}

// GetCrypto takes the Crypto Input request, searches for Crytporaphic usages and returns a CrytoOutput struct
func (d CryptoUseCase) GetCrypto(request dtos.CryptoInput) (dtos.CryptoOutput, error) {

	if len(request.Purls) == 0 {
		zlog.S.Info("Empty List of Purls supplied")
	}
	if len(request.Purls) == 0 {
		zlog.S.Info("Empty List of Purls supplied")
	}
	query := []InternalQuery{}
	purlsToQuery := []utils.PurlReq{}

	//Prepare purls to query
	for _, purl := range request.Purls {

		purlReq := strings.Split(purl.Purl, "@") // Remove any version specific info from the PURL
		if purlReq[0] == "" {
			continue
		}
		if len(purlReq) > 1 {
			purl.Requirement = purlReq[1]
		}

		purlName, err := utils.PurlNameFromString(purl.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err == nil {
			purlsToQuery = append(purlsToQuery, utils.PurlReq{Purl: purlName, Version: purl.Requirement})
		}
		query = append(query, InternalQuery{CompletePurl: purl.Purl, Requirement: purl.Requirement, PurlName: purlName})
	}

	url, err := d.allUrls.GetUrlsByPurlList(purlsToQuery)
	_ = err

	purlMap := make(map[string][]models.AllUrl)

	///Order Urls in a map for fast access by purlname
	for r := range url {
		purlMap[url[r].PurlName] = append(purlMap[url[r].PurlName], url[r])
	}
	urlHashes := []string{}
	// For all the requested purls, choose the closest urls that match
	for r := range query {
		query[r].SelectedURLS, err = models.PickClosestUrls(purlMap[query[r].PurlName], query[r].PurlName, "", query[r].Requirement)
		if len(query[r].SelectedURLS) > 0 {
			query[r].SelectedVersion = query[r].SelectedURLS[0].Version
			for h := range query[r].SelectedURLS {
				urlHashes = append(urlHashes, query[r].SelectedURLS[h].UrlHash)
			}
		}
	}
	//Create a map containing the files for each url
	files := models.QueryBulkPivotLDB(urlHashes)

	//Create a map containing the crypto usage for each file
	crypto := models.QueryBulkCryptoLDB(files)

	mapCrypto := make(map[string][]models.CryptoItem)

	//Remove duplicate algorithms for the same file
	for k, v := range files {
		for f := range v {
			mapCrypto[k] = append(mapCrypto[k], crypto[v[f]]...)
		}
	}
	retV := dtos.CryptoOutput{}

	//Create the response
	for r := range query {
		var cryptoOutItem dtos.CryptoOutputItem
		algorithms := make(map[string]bool)
		relatedURLs := query[r].SelectedURLS
		cryptoOutItem.Version = query[r].SelectedVersion
		cryptoOutItem.Purl = query[r].CompletePurl
		for u := range relatedURLs {

			hash := relatedURLs[u].UrlHash
			items := mapCrypto[hash]
			//remove duplicates for the same URL
			for i := range items {
				if _, exist := algorithms[items[i].Algorithm]; !exist {
					cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: items[i].Algorithm, Strength: items[i].Strenght})
					algorithms[items[i].Algorithm] = true
				}
			}
		}
		retV.Cryptography = append(retV.Cryptography, cryptoOutItem)

	}
	return retV, nil
}
