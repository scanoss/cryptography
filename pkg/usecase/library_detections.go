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

type ECDetectionUseCase struct {
	db         *sqlx.DB
	resolver   *resolver.Resolver
	usageModel *models.ECUsageModel
}

func NewECDetection(db *sqlx.DB, config *myconfig.ServerConfig) *ECDetectionUseCase {
	return &ECDetectionUseCase{
		db:         db,
		resolver:   resolver.New(nil, db),
		usageModel: models.NewECUsageModel(db),
	}
}

// GetDetectionsInRange takes the Crypto Input request, searches for Cryptographic usages and returns a CryptoOutput struct.
func (d ECDetectionUseCase) GetDetectionsInRange(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.ECOutput, error) {
	out := domain.ECOutput{}
	resolved := resolveComponentVersions(ctx, s, d.resolver, components)
	for i := range resolved {
		c := &resolved[i]
		item := domain.ECOutputItem{
			Purl:        components[i].Purl,
			Status:      c.Status,
			Detections:  []domain.ECDetectedItem{},
			Requirement: components[i].Requirement,
			Versions:    []string{},
		}
		// VERSION_NOT_FOUND is acceptable: the resolver pins one version, but a range query
		// inspects every known version against the requirement constraint.
		if c.Status.StatusCode != status.InvalidPurl && c.Status.StatusCode != status.ComponentNotFound {
			item = d.detectionsInRange(ctx, s, item, c.PurlID, c.Versions)
			// Fallback: the package purl has no detections, retry against the source-code purl.
			if item.Status.StatusCode == status.NoInfo {
				if _, _, ok := sourcePurlForFallback(*c); ok {
					srcID, srcVersions := d.sourceVersions(ctx, s, c.SourcePurl.Purl)
					srcItem := d.detectionsInRange(ctx, s, domain.ECOutputItem{
						Purl: components[i].Purl, Requirement: components[i].Requirement,
						Detections: []domain.ECDetectedItem{}, Versions: []string{},
					}, srcID, srcVersions)
					if srcItem.Status.StatusCode == status.Success {
						srcItem.Status = status.ComponentStatus{StatusCode: sourceFallbackStatus, Message: sourceFallbackMessage(c.SourcePurl.Purl)}
						item = srcItem
					}
				}
			}
		}
		out.Hints = append(out.Hints, item)
	}
	return out, nil
}

// GetDetections takes the Crypto Input request, searches for Cryptographic Hints and returns a HintsOutput struct.
//
// This is the single-version endpoint: the resolver pins one version and the hints are read
// for exactly that one. It used to resolve the component to a mining `all_urls` row and query
// by its package hash.
func (d ECDetectionUseCase) GetDetections(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (domain.HintsOutput, error) {
	out := domain.HintsOutput{}
	resolved := resolveComponentVersions(ctx, s, d.resolver, components)
	for i := range resolved {
		c := &resolved[i]
		item := domain.HintsOutputItem{
			Purl:        components[i].Purl,
			Version:     c.Version,
			Requirement: components[i].Requirement,
			Detections:  []domain.ECDetectedItem{},
		}
		switch c.Status.StatusCode {
		case status.InvalidPurl:
			item.Version = ""
			item.Status = status.ComponentStatus{StatusCode: status.InvalidPurl, Message: fmt.Sprintf("Invalid purl: '%s'", components[i].Purl)}
			out.Hints = append(out.Hints, item)
			continue
		case status.ComponentNotFound, status.VersionNotFound:
			item.Status = c.Status
			out.Hints = append(out.Hints, item)
			continue
		}

		uses, err := d.usageModel.GetLibraryUsageByPurlIDs(ctx, s, []string{c.PurlID}, []string{c.Version})
		if err != nil {
			s.Errorf("error getting library detections for purl '%s': %s", components[i].Purl, err)
			item.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without info: '%s'", components[i].Purl)}
			out.Hints = append(out.Hints, item)
			continue
		}
		if len(uses) == 0 {
			item.Status = status.ComponentStatus{StatusCode: status.NoInfo, Message: fmt.Sprintf("Component without  info: '%s'", components[i].Purl)}
			out.Hints = append(out.Hints, item)
			continue
		}
		item.Detections = dedupeDetections(uses)
		item.Status = status.ComponentStatus{StatusCode: status.Success}
		out.Hints = append(out.Hints, item)
	}
	return out, nil
}

// detectionsInRange resolves the in-range versions of a component and the library detections
// they carry. Versions lists only the in-range versions that actually declare a detection.
func (d ECDetectionUseCase) detectionsInRange(ctx context.Context, s *zap.SugaredLogger,
	component domain.ECOutputItem, purlID string, allVersions []string,
) domain.ECOutputItem {
	notFound := func(code status.StatusCode, msg string) domain.ECOutputItem {
		return domain.ECOutputItem{
			Purl:        component.Purl,
			Requirement: component.Requirement,
			Versions:    []string{},
			Detections:  []domain.ECDetectedItem{},
			Status:      status.ComponentStatus{StatusCode: code, Message: msg},
		}
	}
	if purlID == "" || len(allVersions) == 0 {
		return notFound(status.ComponentNotFound, fmt.Sprintf("Component not found '%s'", component.Purl))
	}
	inRange, err := filterVersionsInRange(allVersions, component.Requirement)
	if err != nil {
		return notFound(status.InvalidSemver, fmt.Sprintf("Invalid requirement '%s' for %s", component.Requirement, component.Purl))
	}
	// Component exists but no known version satisfies the requirement.
	if len(inRange) == 0 {
		return notFound(status.VersionNotFound, fmt.Sprintf("No version of %s satisfies '%s'", component.Purl, component.Requirement))
	}
	uses, err := d.usageModel.GetLibraryUsageByPurlIDs(ctx, s, []string{purlID}, inRange)
	if err != nil {
		s.Errorf("error getting library detections for purl '%s': %s", component.Purl, err)
		return notFound(status.NoInfo, fmt.Sprintf("Component without info '%s'", component.Purl))
	}
	if len(uses) == 0 {
		return notFound(status.NoInfo, fmt.Sprintf("Component without info '%s'", component.Purl))
	}

	versions := make([]string, 0, len(inRange))
	seenVersion := make(map[string]bool, len(inRange))
	for _, u := range uses {
		if !seenVersion[u.Version] {
			seenVersion[u.Version] = true
			versions = append(versions, u.Version)
		}
	}
	sortVersionStrings(versions)

	return domain.ECOutputItem{
		Purl:        component.Purl,
		Requirement: component.Requirement,
		Versions:    versions,
		Detections:  dedupeDetections(uses),
		Status:      status.ComponentStatus{StatusCode: status.Success},
	}
}

// dedupeDetections collapses the per-version rows into one entry per library.
// Duplicates should have been removed on mining, but an appended keyword can still
// produce a second row for the same library.
func dedupeDetections(uses []models.ECUsage) []domain.ECDetectedItem {
	seen := make(map[string]bool, len(uses))
	out := make([]domain.ECDetectedItem, 0, len(uses))
	for _, u := range uses {
		if seen[u.ID] {
			continue
		}
		seen[u.ID] = true
		out = append(out, domain.ECDetectedItem{
			ID:          u.ID,
			Name:        u.Name,
			Description: u.Description,
			URL:         u.URL,
			Category:    u.Category,
			Purl:        u.Purl,
		})
	}
	return out
}

// sourceVersions resolves the linked source purl to its own purl_id and version set, so the
// fallback runs the same range query against the source component.
func (d ECDetectionUseCase) sourceVersions(ctx context.Context, s *zap.SugaredLogger, sourcePurl string) (string, []string) {
	resolved, err := d.resolver.Resolve(ctx, sourcePurl, "")
	if err != nil {
		s.Debugf("Failed to resolve source purl '%s': %v", sourcePurl, err)
		return "", nil
	}
	return resolved.PurlID, resolved.Versions
}
