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
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"sort"
	"strings"

	"scanoss.com/cryptography/pkg/utils"

	"github.com/Masterminds/semver/v3"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"

	"github.com/jmoiron/sqlx"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type CryptoMajorUseCase struct {
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewCryptoMajor(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoMajorUseCase {
	return &CryptoMajorUseCase{
		allUrls:     models.NewAllURLModel(db),
		cryptoUsage: models.NewCryptoUsageModel(db),
	}
}

// GetCryptoInRange takes the Crypto Input request, searches for Cryptographic usages and returns a CryptoOutput struct.
func (d CryptoMajorUseCase) GetCryptoInRange(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (dtos.CryptoInRangeOutput, error) {
	if len(components) == 0 {
		s.Info("Empty List of Purls supplied")
		return dtos.CryptoInRangeOutput{}, errors.New("empty list of purls")
	}
	out := dtos.CryptoInRangeOutput{}
	cryptoInRangeItems := []dtos.CryptoInRangeOutputItem{}
	for _, component := range components {
		cryptoInRangeItems = append(cryptoInRangeItems, dtos.CryptoInRangeOutputItem{
			Status:      dtos.ComponentStatus{Status: dtos.Success},
			Purl:        component.Purl,
			Requirement: component.Requirement,
		})
	}
	// Prepare purls to query
	for i, c := range cryptoInRangeItems {
		purl, err := purlhelper.PurlFromString(c.Purl)
		if err != nil {
			s.Errorf("Failed to parse purl '%s': %s", c.Purl, err)
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Failed to parse purl %s", purl), Error: pb.ErrorCode_INVALID_PURL.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue

		}
		if c.Requirement == "*" || strings.HasPrefix(c.Requirement, "v*") {
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Failed to parse purl %s", purl), Error: pb.ErrorCode_INVALID_PURL.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue
		}

		if c.Requirement != "" {
			if !utils.IsValidRequirement(c.Requirement) {
				cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.InvalidSemver, Message: fmt.Sprintf("Invalid semver %s", c.Requirement), Error: pb.ErrorCode_INVALID_SEMVER.Enum()}
				out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
				continue
			}
		}
		purlName, err := purlhelper.PurlNameFromString(c.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			s.Errorf("Failed to parse purl '%s': %s", c.Purl, err)
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Failed to parse purl %s", purl), Error: pb.ErrorCode_INVALID_PURL.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue
		}
		res, err := d.allUrls.GetUrlsByPurlNameTypeInRange(ctx, s, purlName, purl.Type, c.Requirement)
		if err != nil {
			s.Debugf("Failed to get cryptographic algorithms: %v", err)
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", purl), Error: pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue
		}
		if len(res) == 0 {
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", purl), Error: pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue
		}

		var hashes []string
		nonDupVersions := make(map[string]bool)
		mapVersionHash := make(map[string]string)
		for _, url := range res {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
		}
		uses, err1 := d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, hashes)
		if err1 != nil {
			s.Errorf("error getting algorithms usage for purl '%s': %s", c.Purl, err)
		}
		// avoid duplicate algorithms
		nonDupAlgorithms := make(map[models.CryptoItem]bool)
		if len(uses) == 0 {
			cryptoInRangeItems[i].Status = dtos.ComponentStatus{Status: dtos.ComponentWithoutInfo, Message: fmt.Sprintf("Component withput info %s", purl), Error: pb.ErrorCode_NO_INFO.Enum()}
			out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
			continue
		}
		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}]; !exist {
				nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}] = true
				cryptoInRangeItems[i].Algorithms = append(cryptoInRangeItems[i].Algorithms, dtos.CryptoUsageItem{Algorithm: alg.Algorithm, Strength: alg.Strength})
			}
		}
		for k := range nonDupVersions {
			cryptoInRangeItems[i].Versions = append(cryptoInRangeItems[i].Versions, k)
		}

		sort.Slice(cryptoInRangeItems[i].Versions, func(j, k int) bool {
			versionA, _ := semver.NewVersion(cryptoInRangeItems[i].Versions[j])
			versionB, _ := semver.NewVersion(cryptoInRangeItems[i].Versions[k])

			return versionA.LessThan(versionB)
		})

		out.Cryptography = append(out.Cryptography, cryptoInRangeItems[i])
	}
	return out, nil
}
