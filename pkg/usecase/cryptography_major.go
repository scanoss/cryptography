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

	"github.com/jmoiron/sqlx"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/resolver"
)

type CryptoMajorUseCase struct {
	db          *sqlx.DB
	resolver    *resolver.Resolver
	cryptoUsage *models.CryptoUsageModel
}

func NewCryptoMajor(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoMajorUseCase {
	return &CryptoMajorUseCase{
		db:          db,
		resolver:    resolver.New(nil, db),
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
	resolved := resolveComponentVersions(ctx, s, d.resolver, components)
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
			d.fillCryptoInRange(ctx, s, &cryptoItem, c.PurlID, c.Versions)
			// Fallback: the package purl has no crypto info, retry against the source-code purl.
			if cryptoItem.Status.StatusCode == status.NoInfo {
				if hasSourcePurl(*c) {
					srcItem := domain.CryptoInRangeOutputItem{
						Purl: components[i].Purl, Requirement: components[i].Requirement,
						Versions: []string{}, Algorithms: []domain.CryptoUsageItem{},
					}
					srcID, srcVersions := d.sourceVersions(ctx, s, c.SourcePurl.Purl)
					d.fillCryptoInRange(ctx, s, &srcItem, srcID, srcVersions)
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

// fillCryptoInRange resolves the versions in range and their cryptographic algorithms for a
// single component, mutating the output item's Status, Versions and Algorithms accordingly.
//
// The version set now comes from the resolved component (serving `component_version`) rather
// than from a set of mining `all_urls` rows, and the algorithms are read per version, so
// Versions lists exactly the in-range versions that actually declare cryptography.
func (d CryptoMajorUseCase) fillCryptoInRange(ctx context.Context, s *zap.SugaredLogger,
	c *domain.CryptoInRangeOutputItem, purlID string, allVersions []string,
) {
	if purlID == "" || len(allVersions) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", c.Purl)}
		return
	}
	inRange, err := filterVersionsInRange(allVersions, c.Requirement)
	if err != nil {
		c.Status = status.ComponentStatus{StatusCode: status.InvalidSemver, Message: fmt.Sprintf("Invalid requirement '%s' for %s", c.Requirement, c.Purl)}
		return
	}
	// Component exists but no known version satisfies the requirement.
	if len(inRange) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.VersionNotFound, Message: fmt.Sprintf("No version of %s satisfies '%s'", c.Purl, c.Requirement)}
		return
	}
	uses, err := d.cryptoUsage.GetCryptoUsageByPurlIDs(ctx, s, []string{purlID}, inRange)
	if err != nil {
		s.Errorf("error getting algorithms usage for purl '%s': %s", c.Purl, err)
	}
	if len(uses) == 0 {
		c.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info %s", c.Purl)}
		return
	}
	// Report only the in-range versions that carry cryptography, and the union of
	// their algorithms.
	nonDupVersions := make(map[string]bool)
	nonDupAlgorithms := make(map[models.CryptoItem]bool)
	for _, alg := range uses {
		nonDupVersions[alg.Version] = true
		item := models.CryptoItem{Algorithm: alg.Algorithm, Strength: alg.Strength}
		if !nonDupAlgorithms[item] {
			nonDupAlgorithms[item] = true
			c.Algorithms = append(c.Algorithms, domain.CryptoUsageItem{Algorithm: alg.Algorithm, Strength: alg.Strength})
		}
	}
	for k := range nonDupVersions {
		c.Versions = append(c.Versions, k)
	}
	sortVersionStrings(c.Versions)
	c.Status = status.ComponentStatus{StatusCode: status.Success}
}

// sourceVersions resolves the linked source purl to its own purl_id and version
// set, so the fallback runs the same range query against the source component.
func (d CryptoMajorUseCase) sourceVersions(ctx context.Context, s *zap.SugaredLogger, sourcePurl string) (string, []string) {
	resolved, err := d.resolver.Resolve(ctx, sourcePurl, "")
	if err != nil {
		s.Debugf("Failed to resolve source purl '%s': %v", sourcePurl, err)
		return "", nil
	}
	return resolved.PurlID, resolved.Versions
}
