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
	"scanoss.com/cryptography/pkg/domain"
	"sort"

	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"

	"github.com/jmoiron/sqlx"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type VersionsUsingCrypto struct {
	ctx         context.Context
	s           *zap.SugaredLogger
	conn        *sqlx.Conn
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}

func NewVersionsUsingCrypto(db *sqlx.DB, config *myconfig.ServerConfig) *VersionsUsingCrypto {
	return &VersionsUsingCrypto{
		allUrls:     models.NewAllURLModel(db),
		cryptoUsage: models.NewCryptoUsageModel(db),
	}
}

// GetVersionsInRangeUsingCrypto takes the Crypto Input request, searches for Cryptographic and return versions that use and does not use crypto.
func (d VersionsUsingCrypto) GetVersionsInRangeUsingCrypto(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.VersionsInRangeOutput, error) {
	if len(components) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return domain.VersionsInRangeOutput{}, errors.New("empty list of purls")
	}
	out := domain.VersionsInRangeOutput{}
	for _, component := range components {
		status, packageURL, purlName := parseAndValidateComponent(s, component)
		versionInRangeOutput := domain.VersionsInRangeUsingCryptoItem{
			Purl:            component.Purl,
			Status:          status,
			Requirement:     component.Requirement,
			VersionsWith:    []string{},
			VersionsWithout: []string{},
			PackageUrl:      packageURL,
			PurlName:        purlName,
		}
		out.Versions = append(out.Versions, versionInRangeOutput)
	}

	// Prepare purls to query
	for i := range out.Versions {
		component := &out.Versions[i]
		if component.Status.StatusCode != domain.Success {
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameTypeInRange(ctx, s, *component.PurlName, component.PackageUrl.Type, component.Requirement)
		if len(res) == 0 {
			component.Status = domain.ComponentStatus{StatusCode: domain.ComponentNotFound, Message: fmt.Sprintf("Component not found %s", component.Purl), Error: pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()}
			continue
		}
		_ = errQ
		var hashes []string
		nonDupVersions := make(map[string]bool)
		mapVersionHash := make(map[string]string)
		for _, url := range res {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
			nonDupVersions[url.SemVer] = false
		}
		uses, err1 := d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, hashes)
		if err1 != nil {
			d.s.Infof("error getting algorithms usage for purl '%s': %s", component.Purl, err1)
			component.Status = domain.ComponentStatus{StatusCode: domain.ComponentWithoutInfo, Message: fmt.Sprintf("Component without info %s"), Error: pb.ErrorCode_NO_INFO.Enum()}
			continue
		}
		if len(uses) == 0 {
			component.Status = domain.ComponentStatus{StatusCode: domain.ComponentWithoutInfo, Message: fmt.Sprintf("Component without info %s", component.Purl), Error: pb.ErrorCode_NO_INFO.Enum()}
			continue
		}
		for _, alg := range uses {
			nonDupVersions[mapVersionHash[alg.URLHash]] = true
		}
		for k, v := range nonDupVersions {
			if v {
				component.VersionsWith = append(component.VersionsWith, k)
			} else {
				component.VersionsWithout = append(component.VersionsWithout, k)
			}
		}
		sort.Strings(component.VersionsWith)
		sort.Strings(component.VersionsWithout)
	}
	return out, nil
}
