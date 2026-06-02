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

	"github.com/jmoiron/sqlx"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/utils"
)

type VersionsUsingCrypto struct {
	db          *sqlx.DB
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewVersionsUsingCrypto(db *sqlx.DB, config *myconfig.ServerConfig) *VersionsUsingCrypto {
	return &VersionsUsingCrypto{
		db:          db,
		allUrls:     models.NewAllURLModel(db),
		cryptoUsage: models.NewCryptoUsageModel(db),
	}
}

// GetVersionsInRangeUsingCrypto takes the Crypto Input request, searches for Cryptographic and return versions that use and does not use crypto.
func (d VersionsUsingCrypto) GetVersionsInRangeUsingCrypto(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.VersionsInRangeOutput, error) {
	if len(components) == 0 {
		s.Info("Empty List of Purls supplied")
		return domain.VersionsInRangeOutput{}, errors.New("empty list of purls")
	}
	out := domain.VersionsInRangeOutput{}
	resolved := resolveComponentVersions(ctx, s, d.db, components)
	for i := range resolved {
		c := &resolved[i]
		item := domain.VersionsInRangeUsingCryptoItem{
			Purl:            components[i].Purl,
			Status:          c.Status,
			Requirement:     components[i].Requirement,
			VersionsWith:    []string{},
			VersionsWithout: []string{},
		}
		// VERSION_NOT_FOUND is acceptable: the helper resolves one version, but a range query
		// inspects every known version against the requirement constraint.
		if c.Status.StatusCode != status.InvalidPurl && c.Status.StatusCode != status.ComponentNotFound {
			d.fillVersionsInRange(ctx, s, &item, c.Name, c.PurlType)
			// Fallback: the package purl has no crypto info, retry against the source-code purl.
			if item.Status.StatusCode == status.NoInfo {
				if srcName, srcType, ok := sourcePurlForFallback(*c); ok {
					srcItem := domain.VersionsInRangeUsingCryptoItem{
						Purl: components[i].Purl, Requirement: components[i].Requirement,
						VersionsWith: []string{}, VersionsWithout: []string{},
					}
					d.fillVersionsInRange(ctx, s, &srcItem, srcName, srcType)
					if srcItem.Status.StatusCode == status.Success {
						srcItem.Status = status.ComponentStatus{StatusCode: sourceFallbackStatus, Message: sourceFallbackMessage(c.SourcePurl.Purl)}
						item = srcItem
					}
				}
			}
		}
		out.Versions = append(out.Versions, item)
	}
	return out, nil
}

// fillVersionsInRange splits the versions in range into those that use cryptography and those
// that do not, mutating the output item. Version enumeration is delegated to the model layer
// (GetUrlsByPurlList + filterUrlsInRange) rather than a bespoke range query.
func (d VersionsUsingCrypto) fillVersionsInRange(ctx context.Context, s *zap.SugaredLogger, item *domain.VersionsInRangeUsingCryptoItem, purlName, purlType string) {
	urls, err := d.allUrls.GetUrlsByPurlList(ctx, s, []utils.PurlReq{{Purl: purlName}})
	if err != nil {
		s.Debugf("Failed to get urls for purl '%s': %v", item.Purl, err)
		item.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", item.Purl)}
		return
	}
	// No URLs at all: the component is not in the knowledge base.
	if len(urls) == 0 {
		item.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", item.Purl)}
		return
	}
	res, err := filterUrlsInRange(urls, purlType, item.Requirement)
	if err != nil {
		item.Status = status.ComponentStatus{StatusCode: status.InvalidSemver, Message: fmt.Sprintf("Invalid requirement '%s' for %s", item.Requirement, item.Purl)}
		return
	}
	// Component exists but no known version satisfies the requirement.
	if len(res) == 0 {
		item.Status = status.ComponentStatus{StatusCode: status.VersionNotFound, Message: fmt.Sprintf("No version of %s satisfies '%s'", item.Purl, item.Requirement)}
		return
	}
	var hashes []string
	nonDupVersions := make(map[string]bool)
	mapVersionHash := make(map[string]string)
	for _, url := range res {
		hashes = append(hashes, url.URLHash)
		mapVersionHash[url.URLHash] = url.SemVer
		nonDupVersions[url.SemVer] = false
	}
	uses, err := d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, hashes)
	if err != nil {
		s.Infof("error getting algorithms usage for purl '%s': %s", item.Purl, err)
		item.Status = status.ComponentStatus{StatusCode: status.ComponentWithoutInfo, Message: fmt.Sprintf("Component without info %s", item.Purl)}
		return
	}
	if len(uses) == 0 {
		item.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info %s", item.Purl)}
		return
	}
	for _, alg := range uses {
		nonDupVersions[mapVersionHash[alg.URLHash]] = true
	}
	for k, v := range nonDupVersions {
		if v {
			item.VersionsWith = append(item.VersionsWith, k)
		} else {
			item.VersionsWithout = append(item.VersionsWithout, k)
		}
	}
	sort.Strings(item.VersionsWith)
	sort.Strings(item.VersionsWithout)
	item.Status = status.ComponentStatus{StatusCode: status.Success}
}
