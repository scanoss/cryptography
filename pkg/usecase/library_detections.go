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
	"fmt"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"sort"

	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/domain"

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

type ECDetectionUseCase struct {
	allUrls    *models.AllUrlsModel
	usageModel *models.ECUsageModel
}

func NewECDetection(db *sqlx.DB, config *myconfig.ServerConfig) *ECDetectionUseCase {
	return &ECDetectionUseCase{
		allUrls:    models.NewAllURLModel(db),
		usageModel: models.NewECUsageModel(db),
	}
}

// GetDetectionsInRange takes the Crypto Input request, searches for Cryptographic usages and returns a CryptoOutput struct.
func (d ECDetectionUseCase) GetDetectionsInRange(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.ECOutput, error) {
	out := domain.ECOutput{}
	for _, component := range components {
		status, packageURL, purlName := parseAndValidateComponent(s, component)
		hintOutputItem := domain.ECOutputItem{
			Purl:        component.Purl,
			Status:      status,
			Detections:  []domain.ECDetectedItem{},
			Requirement: component.Requirement,
			PackageURL:  packageURL,
			PurlName:    purlName,
		}
		out.Hints = append(out.Hints, hintOutputItem)
	}

	for i, component := range out.Hints {
		if component.Status.StatusCode != status.Success {
			continue
		}
		item := d.processSinglePurl(ctx, s, component)
		out.Hints[i] = item
	}
	return out, nil
}

// GetDetections takes the Crypto Input request, searches for Cryptographic Hints and returns a HintsOutput struct.
func (d ECDetectionUseCase) GetDetections(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.HintsOutput, error) {
	out := domain.HintsOutput{}
	// Prepare purls to query
	for _, component := range components {
		purl, err := purlhelper.PurlFromString(component.Purl)
		if err != nil {
			out.Hints = append(out.Hints, domain.HintsOutputItem{
				Purl: component.Purl, Version: "",
				Requirement: component.Requirement,
				Status:      status.ComponentStatus{StatusCode: status.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl)},
				Detections:  []domain.ECDetectedItem{}})
			continue
		}

		purlName, err := purlhelper.PurlNameFromString(component.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			s.Errorf("Failed to parse purl '%s': %s", component.Purl, err)
			out.Hints = append(out.Hints,
				domain.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      status.ComponentStatus{StatusCode: status.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl)},
					Detections:  []domain.ECDetectedItem{}})
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameType(ctx, s, purlName, purl.Type, component.Requirement)
		if errQ != nil {
			out.Hints = append(out.Hints,
				domain.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      status.ComponentStatus{StatusCode: status.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl)},
					Detections:  []domain.ECDetectedItem{}})
			continue
		}

		uses, err1 := d.usageModel.GetLibraryUsageByURLHashes(ctx, s, []string{res.URLHash})
		if err1 != nil {
			s.Errorf("error getting algorithms usage for purl '%s': %s", component.Purl, err)
			out.Hints = append(out.Hints,
				domain.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info: '%s'", component.Purl)},
					Detections:  []domain.ECDetectedItem{}})
			continue
		}

		if len(uses) == 0 {
			out.Hints = append(out.Hints, domain.HintsOutputItem{
				Purl:        component.Purl,
				Version:     "",
				Requirement: component.Requirement,
				Status:      status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without  info: '%s'", component.Purl)},
				Detections:  []domain.ECDetectedItem{},
			})
			continue
		}

		// avoid duplicate detections (if any)
		// Duplicates should have been removed on mining, but some appended keyword may produce a duplicate entry for an existing url
		nonDupAlgorithms := make(map[string]bool)
		item := domain.HintsOutputItem{Purl: component.Purl, Version: res.Version, Requirement: component.Requirement, Status: status.ComponentStatus{StatusCode: status.Success}}
		for _, alg := range uses {
			//	nonDupVersions[mapVersionHash[alg.URLHash]] = true
			if _, exist := nonDupAlgorithms[alg.ID]; !exist {
				nonDupAlgorithms[alg.ID] = true
				item.Detections = append(item.Detections,
					domain.ECDetectedItem{ID: alg.ID,
						Name:        alg.Name,
						Description: alg.Description,
						URL:         alg.URL,
						Category:    alg.Category,
						Purl:        alg.Purl})
			}
		}
		out.Hints = append(out.Hints, item)
	}
	return out, nil
}

// processURLResults handles the processing of URL results and creates an ECOutputItem.
func (d ECDetectionUseCase) processURLResults(ctx context.Context, s *zap.SugaredLogger, res []models.AllURL, component domain.ECOutputItem) (domain.ECOutputItem, []string) {
	item := domain.ECOutputItem{Purl: component.Purl, Versions: []string{}}
	hashes := make([]string, 0)
	mapVersionHash := make(map[string]string)

	for _, url := range res {
		if url.URLHash != "" {
			hashes = append(hashes, url.URLHash)
			mapVersionHash[url.URLHash] = url.SemVer
		}
	}

	return item, d.processUsages(ctx, s, hashes, mapVersionHash, &item)
}

// processUsages handles library usage processing and returns hashes.
func (d ECDetectionUseCase) processUsages(ctx context.Context, s *zap.SugaredLogger, hashes []string, mapVersionHash map[string]string, item *domain.ECOutputItem) []string {
	uses, err := d.usageModel.GetLibraryUsageByURLHashes(ctx, s, hashes)
	if err != nil {
		s.Errorf("error getting algorithms usage for purl '%s': %s", item.Purl, err)
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
			item.Detections = append(item.Detections, domain.ECDetectedItem{
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
func (d ECDetectionUseCase) processSinglePurl(ctx context.Context, s *zap.SugaredLogger, component domain.ECOutputItem) domain.ECOutputItem {
	componentStatus := status.ComponentStatus{
		StatusCode: status.InvalidPurl,
		Message:    fmt.Sprintf("Invalid purl: '%s'", component.Purl),
	}

	res, err := d.allUrls.GetUrlsByPurlNameTypeInRange(ctx, s, *component.PurlName, component.PackageURL.Type, component.Requirement)
	componentStatus.StatusCode = status.ComponentNotFound
	componentStatus.Message = fmt.Sprintf("Component not found '%s'", component.Purl)
	if err != nil {
		s.Errorf("error getting urls for purl '%s': %s", component.Purl, err)
		return domain.ECOutputItem{Purl: component.Purl, Versions: []string{}, Detections: []domain.ECDetectedItem{}, Status: componentStatus}
	}

	if len(res) == 0 {
		return domain.ECOutputItem{Purl: component.Purl, Versions: []string{}, Detections: []domain.ECDetectedItem{}, Status: componentStatus}
	}
	item, hashes := d.processURLResults(ctx, s, res, component)
	if len(hashes) == 0 {
		componentStatus.StatusCode = status.NoInfo
		componentStatus.Message = fmt.Sprintf("Component without info '%s'", component.Purl)
		return domain.ECOutputItem{Purl: component.Purl, Versions: []string{}, Detections: []domain.ECDetectedItem{}, Status: componentStatus}
	}
	item.Status = status.ComponentStatus{StatusCode: status.Success}
	return item
}
