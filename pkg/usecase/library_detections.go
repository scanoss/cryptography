// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2024 SCANOSS.COM
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
	"strings"

	"scanoss.com/cryptography/pkg/utils"

	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	myconfig "scanoss.com/cryptography/pkg/config"

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type ECDetectionUseCase struct {
	ctx     context.Context
	s       *zap.SugaredLogger
	conn    *sqlx.Conn
	allUrls *models.AllUrlsModel
	usage   *models.ECUsageModel
}

func NewECDetection(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *ECDetectionUseCase {
	return &ECDetectionUseCase{ctx: ctx, s: s, conn: conn,
		allUrls: models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		usage:   models.NewECUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetDetectionsInRange takes the Crypto Input request, searches for Cryptographic usages and returns a CryptoOutput struct.
func (d ECDetectionUseCase) GetDetectionsInRange(components []dtos.ComponentDTO) (dtos.ECOutput, models.QuerySummary, error) {
	if len(components) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.ECOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}

	out := dtos.ECOutput{}
	summary := models.QuerySummary{}
	summary.TotalPurls = len(components)

	for _, component := range components {
		if component.Requirement == "*" || strings.HasPrefix(component.Requirement, "v*") {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, component.Purl)
			d.s.Warnf("requirement should include version range or major and wildcard")
			continue
		}
		if component.Requirement != "" {
			if !utils.IsValidRequirement(component.Requirement) {
				summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, fmt.Sprintf("purl: %s , requirement: %s", component.Purl, component.Requirement))
				continue
			}
		}

		if item, ok := d.processSinglePurl(component, &summary); ok {
			out.Hints = append(out.Hints, *item)
		}
	}

	return out, summary, nil
}

// GetDetections takes the Crypto Input request, searches for Cryptographic Hints and returns a HintsOutput struct.
func (d ECDetectionUseCase) GetDetections(components []dtos.ComponentDTO) (dtos.HintsOutput, models.QuerySummary, error) {
	if len(components) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.HintsOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}
	out := dtos.HintsOutput{}
	summary := models.QuerySummary{}
	summary.TotalPurls = len(components)
	// Prepare purls to query
	for _, component := range components {
		purl, err := purlhelper.PurlFromString(component.Purl)
		if err != nil {
			//	d.s.Logf("Failed to parse purl '%s': %s", reqPurl.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, component.Purl)
			continue
		}

		purlName, err := purlhelper.PurlNameFromString(component.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			d.s.Errorf("Failed to parse purl '%s': %s", component.Purl, err)
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameType(purlName, purl.Type, component.Requirement)
		if errQ != nil {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, purl.Name)
			continue
		}
		item := dtos.HintsOutputItem{Purl: component.Purl, Version: res.Version, Requirement: component.Requirement}
		uses, err1 := d.usage.GetLibraryUsageByURLHashes([]string{res.URLHash})
		if err1 != nil {
			d.s.Errorf("error getting algorithms usage for purl '%s': %s", component.Purl, err)
		}
		// avoid duplicate detections (if any)
		// Duplicates should have been removed on mining, but some appended keyword may produce a duplicate entry for an existing url
		nonDupAlgorithms := make(map[string]bool)
		for _, alg := range uses {
			//	nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[alg.ID]; !exist {
				nonDupAlgorithms[alg.ID] = true
				item.Detections = append(item.Detections,
					dtos.ECDetectedItem{ID: alg.ID,
						Name:        alg.Name,
						Description: alg.Description,
						URL:         alg.URL,
						Category:    alg.Category,
						Purl:        alg.Purl})
			}
		}
		if len(uses) == 0 {
			summary.PurlsWOInfo = append(summary.PurlsWOInfo, component.Purl)
		}
		out.Hints = append(out.Hints, item)
	}
	return out, summary, nil
}

// processURLResults handles the processing of URL results and creates an ECOutputItem.
func (d ECDetectionUseCase) processURLResults(res []models.AllURL, componentDTO dtos.ComponentDTO) (dtos.ECOutputItem, []string) {
	item := dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}}
	hashes := make([]string, 0)
	mapVersionHash := make(map[string]string)

	for _, url := range res {
		if url.URLHash != "" {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
		}
	}

	return item, d.processUsages(hashes, mapVersionHash, &item)
}

// processUsages handles library usage processing and returns hashes.
func (d ECDetectionUseCase) processUsages(hashes []string, mapVersionHash map[string]string, item *dtos.ECOutputItem) []string {
	uses, err := d.usage.GetLibraryUsageByURLHashes(hashes)
	if err != nil {
		d.s.Errorf("error getting algorithms usage for purl '%s': %s", item.Purl, err)
		return hashes
	}
	// If a library has no usages, return empty hashes
	if len(uses) == 0 {
		return []string{}
	}

	nonDupVersions := make(map[string]bool)
	nonDupAlgorithms := make(map[string]bool)

	for _, alg := range uses {
		nonDupVersions[mapVersionHash[alg.URLHash]] = true
		if _, exist := nonDupAlgorithms[alg.ID]; !exist {
			nonDupAlgorithms[alg.ID] = true
			item.Detections = append(item.Detections, dtos.ECDetectedItem{
				ID:          alg.ID,
				Name:        alg.Name,
				Description: alg.Description,
				URL:         alg.URL,
				Category:    alg.Category,
				Purl:        alg.Purl,
			})
		}
	}

	item.Versions = d.getSortedVersions(nonDupVersions)
	return hashes
}

// getSortedVersions returns a sorted slice of versions.
func (d ECDetectionUseCase) getSortedVersions(versions map[string]bool) []string {
	result := make([]string, 0, len(versions))
	for version := range versions {
		result = append(result, version)
	}

	sort.Slice(result, func(i, j int) bool {
		versionA, _ := semver.NewVersion(result[i])
		versionB, _ := semver.NewVersion(result[j])
		return versionA.LessThan(versionB)
	})

	return result
}

// processSinglePurl processes a single PURL and returns whether to continue processing.
func (d ECDetectionUseCase) processSinglePurl(componentDTO dtos.ComponentDTO, summary *models.QuerySummary) (*dtos.ECOutputItem, bool) {
	purl, err := purlhelper.PurlFromString(componentDTO.Purl)
	if err != nil {
		summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, componentDTO.Purl)
		return nil, false
	}

	purlName, err := purlhelper.PurlNameFromString(componentDTO.Purl)
	if err != nil {
		d.s.Errorf("Failed to parse purl '%s': %s", componentDTO.Purl, err)
		summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, componentDTO.Purl)
		return nil, false
	}

	res, err := d.allUrls.GetUrlsByPurlNameTypeInRange(purlName, purl.Type, componentDTO.Requirement, summary)
	if err != nil {
		summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, componentDTO.Purl)
		return nil, false
	}

	if len(res) == 0 {
		summary.PurlsNotFound = append(summary.PurlsNotFound, componentDTO.Purl)
		return nil, false
	}

	item, hashes := d.processURLResults(res, componentDTO)
	if len(hashes) == 0 {
		summary.PurlsWOInfo = append(summary.PurlsWOInfo, componentDTO.Purl)
	}

	return &item, true
}
