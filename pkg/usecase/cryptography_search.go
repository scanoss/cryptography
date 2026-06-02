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
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoUseCase struct {
	db          *sqlx.DB
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}
type CryptoWorkerStruct struct {
	URLMd5  string
	Purl    string
	Version string
}
type ComponentCryptoMetadata struct {
	Purl          string
	ComponentName string
	Requirement   string
	Version       string
	Status        status.ComponentStatus
	SelectedURLS  []models.AllURL
	// SourcePurl is the source-code purl linked by the component helper, used as a
	// fallback target when the original purl has no cryptographic information.
	SourcePurl string
}

func NewCrypto(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoUseCase {
	return &CryptoUseCase{
		db:          db,
		allUrls:     models.NewAllURLModel(db),
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
	componentCryptoMetadata, mapPurls := d.buildMetadata(ctx, s, components)
	s.Debugf("Component Cryptography Metadata: %v", componentCryptoMetadata)
	// Only query with SUCCESS status components
	var successPurlsToQuery []utils.PurlReq
	for _, cm := range componentCryptoMetadata {
		if cm.Status.StatusCode == status.Success {
			successPurlsToQuery = append(successPurlsToQuery, utils.PurlReq{
				Purl:    cm.ComponentName,
				Version: cm.Version,
			})
		}
	}

	// URLs by PurlList (only SUCCESS components)
	var urls []models.AllURL
	var err error
	if len(successPurlsToQuery) > 0 {
		urls, err = d.allUrls.GetUrlsByPurlList(ctx, s, successPurlsToQuery)
		if err != nil {
			s.Warnf("Failed to get list of urls from (%v): %s", successPurlsToQuery, err)
		}
		d.processUrls(urls, componentCryptoMetadata)
	}
	urlHashes := d.collectURLHashes(componentCryptoMetadata)
	var usage []models.CryptoUsage
	if len(urlHashes) > 0 {
		usage, err = d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, urlHashes)
		if err != nil {
			return domain.CryptoOutput{}, errors.New("error retrieving url hashes")
		}
	}

	mapCrypto := d.buildCryptoMap(usage)
	output := d.processCryptoOutput(componentCryptoMetadata, mapCrypto, mapPurls)

	if allowFallback {
		d.applySourceFallback(ctx, s, &output, componentCryptoMetadata, components)
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

func (d CryptoUseCase) processUrls(urls []models.AllURL, componentCryptoMetadata []ComponentCryptoMetadata) {
	// Build a map from PurlName to list of URLs for easy lookup
	urlsByPurl := make(map[string][]models.AllURL)
	for _, u := range urls {
		urlsByPurl[u.PurlName] = append(urlsByPurl[u.PurlName], u)
	}
	// Update component metadata with matched URLs
	for i := range componentCryptoMetadata {
		if componentCryptoMetadata[i].Status.StatusCode == status.Success {
			if matchedUrls, found := urlsByPurl[componentCryptoMetadata[i].ComponentName]; found {
				componentCryptoMetadata[i].SelectedURLS = matchedUrls
			} else {
				componentCryptoMetadata[i].Status = status.ComponentStatus{
					StatusCode: status.ComponentNotFound,
					Message:    fmt.Sprintf("Component %s does not exists", componentCryptoMetadata[i].Purl),
				}
			}
		}
	}
}

// buildMetadata resolves the version requirement of each input component through the shared
// component helper and turns the result into the internal ComponentCryptoMetadata. The helper
// extracts any version embedded in the purl, picks the concrete version matching the requirement
// and reports the component status, so no local purl parsing or version picking is needed here.
func (d CryptoUseCase) buildMetadata(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) ([]ComponentCryptoMetadata, map[string]bool) {
	resolved := resolveComponentVersions(ctx, s, d.db, components)
	componentCryptoMetadata := make([]ComponentCryptoMetadata, 0, len(resolved))
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
		componentCryptoMetadata = append(componentCryptoMetadata,
			ComponentCryptoMetadata{
				Purl:          components[i].Purl,
				Version:       c.Version,
				Status:        c.Status,
				Requirement:   components[i].Requirement,
				ComponentName: c.Name,
				SourcePurl:    srcPurl,
			})
	}
	return componentCryptoMetadata, mapPurls
}

/*func (d CryptoUseCase) buildPurlMap(urls []models.AllURL) map[string][]models.AllURL {
	purlMap := make(map[string][]models.AllURL)
	for _, url := range urls {
		purlMap[url.PurlName] = append(purlMap[url.PurlName], url)
	}
	return purlMap
}*/

func (d CryptoUseCase) collectURLHashes(componentCryptoMetadata []ComponentCryptoMetadata) []string {
	var urlHashes []string
	for i := range componentCryptoMetadata {
		// Skip malformed components
		if componentCryptoMetadata[i].Status.StatusCode != status.Success {
			continue
		}

		// Keep only the URLs for the version the component helper resolved for this requirement.
		var selectedURLs []models.AllURL
		for _, url := range componentCryptoMetadata[i].SelectedURLS {
			if url.Version == componentCryptoMetadata[i].Version {
				selectedURLs = append(selectedURLs, url)
			}
		}
		componentCryptoMetadata[i].SelectedURLS = selectedURLs
		if len(selectedURLs) > 0 {
			componentCryptoMetadata[i].Version = selectedURLs[0].Version
			for _, url := range selectedURLs {
				urlHashes = append(urlHashes, url.URLHash)
			}
		} else {
			// No URLs found for this component
			if componentCryptoMetadata[i].Status.StatusCode != status.ComponentNotFound {
				componentCryptoMetadata[i].Status = status.ComponentStatus{
					StatusCode: status.ComponentNotFound,
					Message:    fmt.Sprintf("Component %s does not exists", componentCryptoMetadata[i].Purl),
				}
			}
			componentCryptoMetadata[i].SelectedURLS = []models.AllURL{}
		}
	}
	return urlHashes
}

func (d CryptoUseCase) buildCryptoMap(usage []models.CryptoUsage) map[string][]models.CryptoItem {
	mapCrypto := make(map[string][]models.CryptoItem)
	for _, v := range usage {
		mapCrypto[v.URLHash] = append(mapCrypto[v.URLHash], models.CryptoItem{
			Algorithm: v.Algorithm,
			Strength:  v.Strength,
		})
	}
	return mapCrypto
}

func (d CryptoUseCase) processCryptoOutput(componentCryptoMetadata []ComponentCryptoMetadata,
	mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) domain.CryptoOutput {
	output := domain.CryptoOutput{}

	for _, c := range componentCryptoMetadata {
		item := d.buildCryptoOutputItem(c, mapCrypto, mapPurls)
		output.Cryptography = append(output.Cryptography, item)
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

func (d CryptoUseCase) buildCryptoOutputItem(q ComponentCryptoMetadata, mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) domain.CryptoOutputItem {
	cryptoOutItem := domain.CryptoOutputItem{
		Version:     q.Version,
		Requirement: q.Requirement,
		Purl:        q.Purl,
		Status:      q.Status,
	}

	if q.Status.StatusCode == status.Success {
		algorithms := make(map[string]bool)
		foundInfo := false

		for _, url := range q.SelectedURLS {
			if items := mapCrypto[url.URLHash]; len(items) > 0 {
				d.processAlgorithms(items, &cryptoOutItem, algorithms)
				foundInfo = true
			}
		}
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
