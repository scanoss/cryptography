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
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/domain"
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
func (d CryptoMajorUseCase) GetCryptoInRange(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.CryptoInRangeOutput, error) {
	if len(components) == 0 {
		s.Info("Empty List of Purls supplied")
		return domain.CryptoInRangeOutput{}, errors.New("empty list of purls")
	}
	out := domain.CryptoInRangeOutput{}
	for _, component := range components {
		status, packageURL, purlName := parseAndValidateComponent(s, component)
		cryptoItem := domain.CryptoInRangeOutputItem{
			Status:      status,
			Purl:        component.Purl,
			Requirement: component.Requirement,
			Versions:    []string{},
			Algorithms:  []domain.CryptoUsageItem{},
			PackageURL:  packageURL,
			PurlName:    purlName,
		}
		out.Cryptography = append(out.Cryptography, cryptoItem)
	}
	// Prepare purls to query
	for i := range out.Cryptography {
		c := &out.Cryptography[i]
		if c.Status.StatusCode != status.Success {
			continue
		}
		res, err := d.allUrls.GetUrlsByPurlNameTypeInRange(ctx, s, *c.PurlName, c.PackageURL.Type, c.Requirement)
		if err != nil {
			s.Debugf("Failed to get cryptographic algorithms: %v", err)
			c.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", c.Purl)}
			continue
		}
		if len(res) == 0 {
			c.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", c.Purl)}
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
			c.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info %s", c.Purl)}
			continue
		}
		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}]; !exist {
				nonDupAlgorithms[models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}] = true
				c.Algorithms = append(c.Algorithms, domain.CryptoUsageItem{Algorithm: alg.Algorithm, Strength: alg.Strength})
			}
		}
		for k := range nonDupVersions {
			c.Versions = append(c.Versions, k)
		}

		sort.Slice(c.Versions, func(j, k int) bool {
			versionA, _ := semver.NewVersion(c.Versions[j])
			versionB, _ := semver.NewVersion(c.Versions[k])

			return versionA.LessThan(versionB)
		})
	}
	return out, nil
}
