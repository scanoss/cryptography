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
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoMajorUseCase struct {
	db          *sqlx.DB
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewCryptoMajor(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoMajorUseCase {
	return &CryptoMajorUseCase{
		db:          db,
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
	resolved := resolveComponentVersions(ctx, s, d.db, components)
	for i := range resolved {
		c := &resolved[i]
		cryptoItem := domain.CryptoInRangeOutputItem{
			Status:      c.Status,
			Purl:        components[i].Purl,
			Requirement: components[i].Requirement,
			Versions:    []string{},
			Algorithms:  []domain.CryptoUsageItem{},
		}
		// Resolve algorithms for components whose purl is valid and that exist in the KB.
		// VERSION_NOT_FOUND is acceptable here: the helper resolves a single version, but a
		// range query still inspects every known version against the requirement constraint.
		if c.Status.StatusCode != status.InvalidPurl && c.Status.StatusCode != status.ComponentNotFound {
			d.fillCryptoInRange(ctx, s, &cryptoItem, c.Name, c.PurlType)
			// Fallback: the package purl has no crypto info, retry against the source-code purl.
			if cryptoItem.Status.StatusCode == status.NoInfo {
				if srcName, srcType, ok := sourcePurlForFallback(*c); ok {
					srcItem := domain.CryptoInRangeOutputItem{
						Purl: components[i].Purl, Requirement: components[i].Requirement,
						Versions: []string{}, Algorithms: []domain.CryptoUsageItem{},
					}
					d.fillCryptoInRange(ctx, s, &srcItem, srcName, srcType)
					if srcItem.Status.StatusCode == status.Success {
						srcItem.Status = status.ComponentStatus{StatusCode: sourceFallbackStatus, Message: sourceFallbackMessage(c.SourcePurl.Purl)}
						cryptoItem = srcItem
					}
				}
			}
		}
		out.Cryptography = append(out.Cryptography, cryptoItem)
	}
	return out, nil
}

// fillCryptoInRange resolves the versions in range and their cryptographic algorithms for a single
// component, mutating the output item's Status, Versions and Algorithms accordingly. Version
// enumeration is delegated to the component helper / model layer (GetUrlsByPurlList +
// filterUrlsInRange) instead of a bespoke range query.
func (d CryptoMajorUseCase) fillCryptoInRange(ctx context.Context, s *zap.SugaredLogger, c *domain.CryptoInRangeOutputItem, purlName, purlType string) {
	urls, err := d.allUrls.GetUrlsByPurlList(ctx, s, []utils.PurlReq{{Purl: purlName}})
	if err != nil {
		s.Debugf("Failed to get urls for purl '%s': %v", c.Purl, err)
		c.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", c.Purl)}
		return
	}
	// No URLs at all: the component is not in the knowledge base.
	if len(urls) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", c.Purl)}
		return
	}
	res, err := filterUrlsInRange(urls, purlType, c.Requirement)
	if err != nil {
		c.Status = status.ComponentStatus{StatusCode: status.InvalidSemver, Message: fmt.Sprintf("Invalid requirement '%s' for %s", c.Requirement, c.Purl)}
		return
	}
	// Component exists but no known version satisfies the requirement.
	if len(res) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.VersionNotFound, Message: fmt.Sprintf("No version of %s satisfies '%s'", c.Purl, c.Requirement)}
		return
	}
	var hashes []string
	nonDupVersions := make(map[string]bool)
	mapVersionHash := make(map[string]string)
	for _, url := range res {
		hashes = append(hashes, url.URLHash)
		mapVersionHash[url.URLHash] = url.SemVer
	}
	uses, err := d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, hashes)
	if err != nil {
		s.Errorf("error getting algorithms usage for purl '%s': %s", c.Purl, err)
	}
	if len(uses) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info %s", c.Purl)}
		return
	}
	// avoid duplicate algorithms
	nonDupAlgorithms := make(map[models.CryptoItem]bool)
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
	c.Status = status.ComponentStatus{StatusCode: status.Success}
}
