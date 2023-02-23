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
	"fmt"
	"github.com/jmoiron/sqlx"
	"scanoss.com/cryptography/pkg/dtos"
	zlog "scanoss.com/cryptography/pkg/logger"
	"scanoss.com/cryptography/pkg/models"
	"strings"
)

type CryptoUseCase struct {
	ctx     context.Context
	conn    *sqlx.Conn
	allUrls *models.AllUrlsModel
}

func NewCrypto(ctx context.Context, conn *sqlx.Conn) *CryptoUseCase {
	return &CryptoUseCase{ctx: ctx, conn: conn,
		allUrls: models.NewAllUrlModel(ctx, conn, models.NewProjectModel(ctx, conn)),
	}
}

// GetCrypto takes the Crypto Input request, searches for Crytporaphic usages and returns a CrytoOutput struct
func (d CryptoUseCase) GetCrypto(request dtos.CryptoInput) (dtos.CryptoOutput, error) {

	var problems = false
	if len(request.Purls) == 0 {
		zlog.S.Info("Empty List of Purls supplied")
	}
	var retV dtos.CryptoOutput
	for _, purl := range request.Purls {
		var cryptoOutItem dtos.CryptoOutputItem
		cryptoOutItem.Purl = strings.Split(purl.Purl, "@")[0] // Remove any version specific info from the PURL
		url, err := d.allUrls.GetUrlsByPurlString(purl.Purl, purl.Requirement)
		_ = url
		if err != nil {
			zlog.S.Errorf("Problem encountered extracting URLs for: %v - %v.", purl, err)
			problems = true
			continue
			// TODO add a placeholder in the response?
		}

		fmt.Printf("URL DATA: %v\n", url)
		/// DO MAGIC with LDB
		/*type CryptoOutput struct {
			Cryptography []CryptoUsage `json:"files"`
		}

		type CryptoOutputItem struct {
			Purl       string             `json:"purl"`
			Version    string             `json:"version"`
			Algorithms []CryptoUsage `json:"algorithms"`
		}

		type CryptoUsageItem struct {
			Algorithm string `json:"name"`
			Strength  string `json:"strength"`
			Usage     int32  `json:"usage"`
		}
		*/
		// Add sme hardcoded value
		cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: "MD5", Strength: "128", Usage: 32})
		cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: "CRC32", Strength: "32", Usage: 32})
		cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{Algorithm: "CRC8", Strength: "8", Usage: 32})
		retV.Cryptography = append(retV.Cryptography, cryptoOutItem)
	}

	if problems {
		zlog.S.Errorf("Encountered issues while processing dependencies: %v", request)
		return dtos.CryptoOutput{}, errors.New("encountered issues while processing dependencies")
	}
	zlog.S.Debugf("Output dependencies: %v", retV)

	return retV, nil
}
