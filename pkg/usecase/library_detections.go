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
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"sort"
	"strings"

	"scanoss.com/cryptography/pkg/utils"

	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	myconfig "scanoss.com/cryptography/pkg/config"

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
func (d ECDetectionUseCase) GetDetectionsInRange(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (dtos.ECOutput, error) {
	out := dtos.ECOutput{}
	for _, component := range components {
		if component.Requirement == "*" || strings.HasPrefix(component.Requirement, "v*") {
			out.Hints = append(out.Hints, dtos.ECOutputItem{
				Purl:     component.Purl,
				Versions: []string{},
				Status:   dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Requirement should include version range or major and wildcard. Requirement: '%s'", component.Requirement), Error: pb.ErrorCode_INVALID_SEMVER.Enum()},
			})
			s.Warnf("requirement should include version range or major and wildcard")
			continue
		}
		if component.Requirement != "" && !utils.IsValidRequirement(component.Requirement) {
			out.Hints = append(out.Hints, dtos.ECOutputItem{
				Purl:     component.Purl,
				Versions: []string{},
				Status:   dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Invald requirement: '%s'", component.Requirement), Error: pb.ErrorCode_INVALID_SEMVER.Enum()},
			})
			continue
		}
		item := d.processSinglePurl(ctx, s, component)
		out.Hints = append(out.Hints, *item)
	}
	return out, nil
}

// GetDetections takes the Crypto Input request, searches for Cryptographic Hints and returns a HintsOutput struct.
func (d ECDetectionUseCase) GetDetections(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (dtos.HintsOutput, error) {
	out := dtos.HintsOutput{}
	// Prepare purls to query
	for _, component := range components {
		purl, err := purlhelper.PurlFromString(component.Purl)
		if err != nil {
			out.Hints = append(out.Hints, dtos.HintsOutputItem{
				Purl: component.Purl, Version: "",
				Requirement: component.Requirement,
				Status:      dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl), Error: pb.ErrorCode_INVALID_PURL.Enum()},
				Detections:  []dtos.ECDetectedItem{}})
			continue
		}

		purlName, err := purlhelper.PurlNameFromString(component.Purl) // Make sure we just have the bare minimum for a Purl Name
		if err != nil {
			s.Errorf("Failed to parse purl '%s': %s", component.Purl, err)
			out.Hints = append(out.Hints,
				dtos.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl), Error: pb.ErrorCode_INVALID_PURL.Enum()},
					Detections:  []dtos.ECDetectedItem{}})
			continue
		}
		res, errQ := d.allUrls.GetUrlsByPurlNameType(ctx, s, purlName, purl.Type, component.Requirement)
		if errQ != nil {
			out.Hints = append(out.Hints,
				dtos.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      dtos.ComponentStatus{Status: dtos.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", component.Purl), Error: pb.ErrorCode_INVALID_PURL.Enum()},
					Detections:  []dtos.ECDetectedItem{}})
			continue
		}

		uses, err1 := d.usageModel.GetLibraryUsageByURLHashes(ctx, s, []string{res.URLHash})
		if err1 != nil {
			s.Errorf("error getting algorithms usage for purl '%s': %s", component.Purl, err)
			out.Hints = append(out.Hints,
				dtos.HintsOutputItem{
					Purl:        component.Purl,
					Version:     "",
					Requirement: component.Requirement,
					Status:      dtos.ComponentStatus{Status: dtos.ComponentNotFound, Message: fmt.Sprintf("Component not found: '%s'", component.Purl), Error: pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()},
					Detections:  []dtos.ECDetectedItem{}})
			continue
		}

		if len(uses) == 0 {
			out.Hints = append(out.Hints, dtos.HintsOutputItem{
				Purl:        component.Purl,
				Version:     "",
				Requirement: component.Requirement,
				Status:      dtos.ComponentStatus{Status: dtos.ComponentWithoutInfo, Message: fmt.Sprintf("Component with out  info: '%s'", component.Purl), Error: pb.ErrorCode_NO_INFO.Enum()},
				Detections:  []dtos.ECDetectedItem{},
			})
			continue
		}

		// avoid duplicate detections (if any)
		// Duplicates should have been removed on mining, but some appended keyword may produce a duplicate entry for an existing url
		nonDupAlgorithms := make(map[string]bool)
		item := dtos.HintsOutputItem{Purl: component.Purl, Version: res.Version, Requirement: component.Requirement, Status: dtos.ComponentStatus{Status: dtos.Success}}
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
		out.Hints = append(out.Hints, item)
	}
	return out, nil
}

// processURLResults handles the processing of URL results and creates an ECOutputItem.
func (d ECDetectionUseCase) processURLResults(ctx context.Context, s *zap.SugaredLogger, res []models.AllURL, componentDTO dtos.ComponentDTO) (dtos.ECOutputItem, []string) {
	item := dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}}
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
func (d ECDetectionUseCase) processUsages(ctx context.Context, s *zap.SugaredLogger, hashes []string, mapVersionHash map[string]string, item *dtos.ECOutputItem) []string {
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
func (d ECDetectionUseCase) processSinglePurl(ctx context.Context, s *zap.SugaredLogger, componentDTO dtos.ComponentDTO) *dtos.ECOutputItem {
	purl, err := purlhelper.PurlFromString(componentDTO.Purl)
	componentStatus := dtos.ComponentStatus{
		Status:  dtos.InvalidPurl,
		Message: fmt.Sprintf("Invalid purl: '%s'", componentDTO.Purl),
		Error:   pb.ErrorCode_INVALID_PURL.Enum(),
	}
	if err != nil {
		return &dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}, Detections: []dtos.ECDetectedItem{}, Status: componentStatus}
	}

	purlName, err := purlhelper.PurlNameFromString(componentDTO.Purl)
	if err != nil {
		s.Errorf("Failed to parse purl '%s': %s", componentDTO.Purl, err)
		return &dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}, Detections: []dtos.ECDetectedItem{}, Status: componentStatus}
	}

	res, err := d.allUrls.GetUrlsByPurlNameTypeInRange(ctx, s, purlName, purl.Type, componentDTO.Requirement)
	componentStatus.Status = dtos.ComponentNotFound
	componentStatus.Message = fmt.Sprintf("Component not found '%s'", componentDTO.Purl)
	componentStatus.Error = pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()
	if err != nil {
		return &dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}, Detections: []dtos.ECDetectedItem{}, Status: componentStatus}
	}

	if len(res) == 0 {
		return &dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}, Detections: []dtos.ECDetectedItem{}, Status: componentStatus}
	}

	item, hashes := d.processURLResults(ctx, s, res, componentDTO)
	if len(hashes) == 0 {
		componentStatus.Status = dtos.ComponentWithoutInfo
		componentStatus.Message = fmt.Sprintf("Component without info '%s'", componentDTO.Purl)
		componentStatus.Error = pb.ErrorCode_NO_INFO.Enum()
		return &dtos.ECOutputItem{Purl: componentDTO.Purl, Versions: []string{}, Detections: []dtos.ECDetectedItem{}, Status: componentStatus}
	}
	item.Status = dtos.ComponentStatus{Status: dtos.Success}
	return &item
}
