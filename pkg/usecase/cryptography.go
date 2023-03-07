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

	"github.com/jmoiron/sqlx"
	"scanoss.com/cryptography/pkg/dtos"
	zlog "scanoss.com/cryptography/pkg/logger"
	"scanoss.com/cryptography/pkg/models"
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

func NewCrypto(ctx context.Context, conn *sqlx.Conn) *CryptoUseCase {
	return &CryptoUseCase{ctx: ctx, conn: conn,
		allUrls: models.NewAllUrlModel(ctx, conn, models.NewProjectModel(ctx, conn)),
	}
}

// GetCrypto takes the Crypto Input request, searches for Crytporaphic usages and returns a CrytoOutput struct
func (d CryptoUseCase) GetCrypto(request dtos.CryptoInput) (dtos.CryptoOutput, error) {
	var toRequest []CryptoWorkerStruct
	var problems = false
	if len(request.Purls) == 0 {
		zlog.S.Info("Empty List of Purls supplied")
	}
	if len(request.Purls) == 0 {
		zlog.S.Info("Empty List of Purls supplied")
	}

	for _, purl := range request.Purls {

		var cryptoOutItem dtos.CryptoOutputItem
		purlReq := strings.Split(purl.Purl, "@")[0] // Remove any version specific info from the PURL
		if purlReq == "" {
			continue
		}

		url, err := d.allUrls.GetUrlsByPurlString(purl.Purl, purl.Requirement)
		cryptoOutItem.Version = url.SemVer

		_ = url
		if err != nil || url.PurlName == "" || url.UrlHash == "" {
			zlog.S.Errorf("Problem encountered extracting URLs for: %v - %v.", purl, err)
			problems = true
			continue
			// TODO add a placeholder in the response?
		} else {

			if url.UrlHash != "" {
				r := CryptoWorkerStruct{URLMd5: url.UrlHash, Purl: purlReq, Version: url.SemVer}
				if purlReq != "" && url.UrlHash != "" {
					toRequest = append(toRequest, r)
				}
			}
		}
	}

	jobs := make(chan CryptoWorkerStruct)
	results := make(chan dtos.CryptoOutputItem, len(toRequest))
	var retV dtos.CryptoOutput
	workers := 2
	if len(toRequest) >= 2 {
		workers = 1
	}

	for w := 1; w <= workers; w++ {
		go d.workerPurl(w, jobs, results)
	}
	jobCount := 0

	if len(request.Purls) > 0 {
		for job := range toRequest {
			if toRequest[job].Purl != "" {
				jobs <- toRequest[job]
				jobCount++

			}
		}
		close(jobs)

		for _, purl := range toRequest {
			_ = purl
			res := <-results
			retV.Cryptography = append(retV.Cryptography, res)
		}
	}

	if problems {
		zlog.S.Errorf("Encountered issues while processing cryptography: %v", request)
		return dtos.CryptoOutput{}, errors.New("encountered issues while processing cryptography")
	}
	zlog.S.Debugf("Output cryptography: %v", retV)

	return retV, nil
}

func (d CryptoUseCase) workerPurl(id int, jobs <-chan CryptoWorkerStruct, resultsChan chan<- dtos.CryptoOutputItem) {

	for jo := range jobs {
		var cryptoOutItem dtos.CryptoOutputItem
		cryptoOutItem.Purl = jo.Purl // Remove any version specific info from the PURL

		cryptoOutItem.Version = jo.Version
		algorithms := models.GetCryptoByURL(jo.URLMd5)
		for a := range algorithms {
			cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: algorithms[a].Algorithm, Strength: algorithms[a].Strenght})
		}
		resultsChan <- cryptoOutItem
	}
}
