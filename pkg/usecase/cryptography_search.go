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
	"strings"

	"github.com/jmoiron/sqlx"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/resolver"
)

type CryptoUseCase struct {
	db          *sqlx.DB
	resolver    *resolver.Resolver
	cryptoUsage *models.CryptoUsageModel
}

// ComponentCryptoMetadata is the per-component working state of a crypto lookup.
//
// It used to carry SelectedURLS, the mining `all_urls` rows whose package hashes
// keyed the crypto tables. Serving keys crypto by (purl_id, version), so the
// component's own identity is all that is needed.
type ComponentCryptoMetadata struct {
	Purl          string
	ComponentName string
	PurlType      string
	Requirement   string
	Version       string
	// PurlID is the serving component.purl_id the crypto rows hang off.
	PurlID string
	Status status.ComponentStatus
	// SourcePurl is the source-code purl linked by the resolver, used as a
	// fallback target when the original purl has no cryptographic information.
	SourcePurl string
}

func NewCrypto(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoUseCase {
	return &CryptoUseCase{
		db:          db,
		resolver:    resolver.New(nil, db),
		cryptoUsage: models.NewCryptoUsageModel(db),
	}
}

// GetComponentsAlgorithms takes a list of ComponentDTO objects, searches for cryptographic usages and returns a CryptoOutput struct.
func (d CryptoUseCase) GetComponentsAlgorithms(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.CryptoOutput, error) {
	return d.getComponentsAlgorithms(ctx, s, components, true)
}

// getComponentsAlgorithms resolves cryptographic usages for the given components. When allowFallback
// is true, components that resolve with no crypto info are retried against their source-code purl.
func (d CryptoUseCase) getComponentsAlgorithms(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO, allowFallback bool) (domain.CryptoOutput, error) {
	if len(components) == 0 {
		s.Info("Empty List of Purls supplied")
		return domain.CryptoOutput{}, errors.New("empty list of purls")
	}
	metadata, mapPurls := d.buildMetadata(ctx, s, components)
	s.Debugf("Component Cryptography Metadata: %v", metadata)

	// One query for the whole batch: every resolved (purl_id, version) pair at once.
	var purlIDs, versions []string
	for _, cm := range metadata {
		if cm.Status.StatusCode == status.Success && cm.PurlID != "" {
			purlIDs = append(purlIDs, cm.PurlID)
			versions = append(versions, cm.Version)
		}
	}
	var usage []models.CryptoUsage
	if len(purlIDs) > 0 {
		var err error
		usage, err = d.cryptoUsage.GetCryptoUsageByPurlIDs(ctx, s, purlIDs, versions)
		if err != nil {
			return domain.CryptoOutput{}, errors.New("error retrieving cryptographic usage")
		}
	}

	mapCrypto := d.buildCryptoMap(usage)
	output := d.processCryptoOutput(metadata, mapCrypto, mapPurls)

	if allowFallback {
		d.applySourceFallback(ctx, s, &output, metadata, components)
	}
	return output, nil
}

// applySourceFallback retries components that resolved with no crypto info against their linked
// source-code purl. When the source purl yields crypto, the result replaces the original item
// (keeping the original purl/requirement) and is flagged with a warning status so callers know
// the data comes from the upstream source. The retry runs with fallback disabled to bound depth.
func (d CryptoUseCase) applySourceFallback(
	ctx context.Context, s *zap.SugaredLogger, output *domain.CryptoOutput,
	metadata []ComponentCryptoMetadata, components []dtos.ComponentDTO,
) {
	var srcDTOs []dtos.ComponentDTO
	var outIdx []int
	for i := range output.Cryptography {
		code := output.Cryptography[i].Status.StatusCode
		if (code == status.NoInfo || code == status.ComponentWithoutInfo) && metadata[i].SourcePurl != "" {
			srcDTOs = append(srcDTOs, dtos.ComponentDTO{Purl: metadata[i].SourcePurl, Requirement: components[i].Requirement})
			outIdx = append(outIdx, i)
		}
	}
	if len(srcDTOs) == 0 {
		return
	}
	srcOut, err := d.getComponentsAlgorithms(ctx, s, srcDTOs, false)
	if err != nil {
		s.Warnf("Source-purl crypto fallback failed: %v", err)
		return
	}
	for j := range srcOut.Cryptography {
		src := srcOut.Cryptography[j]
		if src.Status.StatusCode != status.Success {
			continue
		}
		i := outIdx[j]
		src.Purl = output.Cryptography[i].Purl
		src.Requirement = output.Cryptography[i].Requirement
		src.Status = status.ComponentStatus{StatusCode: sourceFallbackStatus, Message: sourceFallbackMessage(metadata[i].SourcePurl)}
		output.Cryptography[i] = src
	}
}

// buildMetadata resolves the version requirement of each input component against the serving
// schema and turns the result into the internal ComponentCryptoMetadata. The resolver extracts
// any version embedded in the purl, picks the concrete version matching the requirement and
// reports the component status, so no local purl parsing or version picking is needed here.
func (d CryptoUseCase) buildMetadata(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) ([]ComponentCryptoMetadata, map[string]bool) {
	resolved := resolveComponentVersions(ctx, s, d.resolver, components)
	metadata := make([]ComponentCryptoMetadata, 0, len(resolved))
	mapPurls := make(map[string]bool)
	for i := range resolved {
		c := resolved[i]
		s.Debugf("Resolved purl: %v, Name: %s, Version: %s, Status: %s", c.OriginalPurl, c.Name, c.Version, c.Status.StatusCode)
		if c.Status.StatusCode == status.Success {
			mapPurls[c.Name] = false
		}
		var srcPurl string
		if _, _, ok := sourcePurlForFallback(c); ok {
			srcPurl = c.SourcePurl.Purl
		}
		metadata = append(metadata, ComponentCryptoMetadata{
			Purl:          components[i].Purl,
			Version:       c.Version,
			Status:        c.Status,
			Requirement:   components[i].Requirement,
			ComponentName: c.Name,
			PurlType:      c.PurlType,
			PurlID:        c.PurlID,
			SourcePurl:    srcPurl,
		})
	}
	return metadata, mapPurls
}

// cryptoKey addresses one component version in the crypto map. Keying on the
// purl_id as well as the version is what stops two components that happen to
// share a version string from picking up each other's algorithms.
type cryptoKey struct {
	purlID  string
	version string
}

func (d CryptoUseCase) buildCryptoMap(usage []models.CryptoUsage) map[cryptoKey][]models.CryptoItem {
	mapCrypto := make(map[cryptoKey][]models.CryptoItem)
	for _, v := range usage {
		key := cryptoKey{purlID: v.PurlID, version: v.Version}
		mapCrypto[key] = append(mapCrypto[key], models.CryptoItem{
			Algorithm: v.Algorithm,
			Strength:  v.Strength,
		})
	}
	return mapCrypto
}

func (d CryptoUseCase) processCryptoOutput(metadata []ComponentCryptoMetadata,
	mapCrypto map[cryptoKey][]models.CryptoItem, mapPurls map[string]bool) domain.CryptoOutput {
	output := domain.CryptoOutput{}
	for _, c := range metadata {
		output.Cryptography = append(output.Cryptography, d.buildCryptoOutputItem(c, mapCrypto, mapPurls))
	}
	return output
}

func (d CryptoUseCase) processAlgorithms(items []models.CryptoItem, cryptoOutItem *domain.CryptoOutputItem, algorithms map[string]bool) {
	for _, item := range items {
		algKey := strings.ToLower(item.Algorithm)
		if !algorithms[algKey] {
			cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, domain.CryptoUsageItem{
				Algorithm: algKey,
				Strength:  item.Strength,
			})
			algorithms[algKey] = true
		}
	}
}

func (d CryptoUseCase) buildCryptoOutputItem(q ComponentCryptoMetadata, mapCrypto map[cryptoKey][]models.CryptoItem, mapPurls map[string]bool) domain.CryptoOutputItem {
	cryptoOutItem := domain.CryptoOutputItem{
		Version:     q.Version,
		Requirement: q.Requirement,
		Purl:        q.Purl,
		Status:      q.Status,
	}

	if q.Status.StatusCode == status.Success {
		algorithms := make(map[string]bool)
		items := mapCrypto[cryptoKey{purlID: q.PurlID, version: q.Version}]
		foundInfo := len(items) > 0
		d.processAlgorithms(items, &cryptoOutItem, algorithms)
		// Update status based on whether we found crypto info
		if !foundInfo {
			cryptoOutItem.Status = status.ComponentStatus{
				StatusCode: status.ComponentWithoutInfo,
				Message:    fmt.Sprintf("No info found for %s", q.Purl)}
		}
		mapPurls[q.ComponentName] = foundInfo
	}

	return cryptoOutItem
}
