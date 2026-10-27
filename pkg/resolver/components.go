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

package resolver

import (
	"context"
	"errors"
	"strings"
	"sync"

	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"go.uber.org/zap"
)

// defaultMaxWorkers matches go-component-helper's default fan-out.
const defaultMaxWorkers = 5

// Resolution carries a resolved component alongside the serving purl_id its
// crypto rows are keyed by. The embedded Component keeps the shape the rest of
// the service already works with; PurlID is what the new queries need.
type Resolution struct {
	compHelper.Component
	// PurlID is the serving `component.purl_id`, empty when the component did
	// not resolve.
	PurlID string
	// SourcePurlID is the purl_id of the linked source component, empty when
	// there is no source link.
	SourcePurlID string
}

// ResolveComponents turns the request DTOs into resolved components.
//
// It is the serving replacement for compHelper.GetComponentsVersion, which
// resolved against the mining tables `all_urls`, `mines` and `versions` - none of
// which the serving schema has. The embedded Component is populated the same way
// the helper populated it, including the SourcePurl the fallback paths read, so
// the callers keep working unchanged.
func ResolveComponents(ctx context.Context, s *zap.SugaredLogger, r *Resolver,
	componentDTOs []compHelper.ComponentDTO, maxWorkers int,
) []Resolution {
	resolutions := SanitiseComponents(s, componentDTOs)
	if len(resolutions) == 0 {
		return nil
	}
	if maxWorkers <= 0 {
		maxWorkers = defaultMaxWorkers
	}

	jobs := make(chan int, len(resolutions))
	wg := sync.WaitGroup{}
	for i := 0; i < min(maxWorkers, len(resolutions)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				resolveOne(ctx, s, r, &resolutions[idx])
			}
		}()
	}
	for i := range resolutions {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return resolutions
}

// resolveOne fills in the purl_id, version, version set, source purl and status
// for one already-sanitised component. Components that failed sanitisation keep
// the status they were given.
func resolveOne(ctx context.Context, s *zap.SugaredLogger, r *Resolver, res *Resolution) {
	if res.Status.StatusCode != domain.Success {
		return
	}
	res.Versions = []string{}

	resolved, err := r.Resolve(ctx, res.Purl, res.Requirement)
	switch {
	case errors.Is(err, ErrComponentNotFound), errors.Is(err, ErrInvalidPurl), errors.Is(err, ErrEmptyPurl):
		s.Warnf("Purl doesn't exist: %s, %v", res.Purl, err)
		res.Status = domain.ComponentStatus{Message: "Component not found", StatusCode: domain.ComponentNotFound}
		return
	case err != nil:
		s.Errorf("Failed to resolve component %s (%s): %v", res.Purl, res.Requirement, err)
		res.Status = domain.ComponentStatus{Message: "Component not found", StatusCode: domain.ComponentNotFound}
		return
	}

	res.PurlID = resolved.PurlID
	res.Versions = resolved.Versions
	res.SourcePurl = sourcePurl(s, resolved.SourcePurl)
	if resolved.SourcePurl != nil {
		res.SourcePurlID = resolved.SourcePurl.PurlID
	}

	// The component exists, so its version set and source link are reported
	// either way; only the status and the pinned version differ.
	if resolved.StatusCode == StatusVersionNotFound {
		s.Warnf("Failed to get component version: %s, %s", res.Purl, res.Requirement)
		res.Status = domain.ComponentStatus{Message: "Component version not found", StatusCode: domain.VersionNotFound}
		return
	}
	if len(resolved.Version) > 0 {
		res.Version = resolved.Version
	}
}

// sourcePurl converts a resolved source link into the helper's SourcePurl, which
// is what the per-endpoint fallbacks read. Mining built this from the `projects`
// table's source-mine columns; serving links it through `component.source_purl_id`.
func sourcePurl(s *zap.SugaredLogger, src *SourcePurl) *compHelper.SourcePurl {
	if src == nil {
		return nil
	}
	info, err := purlInfo(s, src.Purl)
	if err != nil {
		s.Warnf("Failed to parse source PURL %q: %v", src.Purl, err)
		return &compHelper.SourcePurl{
			Status: domain.ComponentStatus{Message: "Source component not found", StatusCode: domain.ComponentNotFound},
		}
	}
	return &compHelper.SourcePurl{PurlInfo: info, Status: domain.ComponentStatus{StatusCode: domain.Success}}
}

// SanitiseComponents validates and normalises the request DTOs.
//
// A port of go-component-helper's unexported sanitiseComponents, kept faithful to
// it because it defines the service's input contract: an empty or unparseable
// purl is rejected with INVALID_PURL, and a version carried in the purl is moved
// into the requirement, taking precedence over any requirement supplied.
//
// The version is stripped with a string replace on the original purl rather than
// by re-rendering the parsed purl, so percent-encoding survives: scoped npm
// packages are stored as pkg:npm/%40scope/name, not pkg:npm/@scope/name, and
// re-rendering would break the database lookup.
func SanitiseComponents(s *zap.SugaredLogger, componentDTOs []compHelper.ComponentDTO) []Resolution {
	resolutions := make([]Resolution, 0, len(componentDTOs))
	for _, dto := range componentDTOs {
		if len(dto.Purl) == 0 {
			resolutions = append(resolutions, invalid(compHelper.PurlInfo{Purl: dto.Purl}, dto, dto.Requirement, "Empty Purl"))
			continue
		}
		originalPurl, originalRequirement := dto.Purl, dto.Requirement

		info, version, err := purlInfoWithVersion(s, dto.Purl)
		if err != nil {
			s.Warnf("Failed to parse PURL %q (requirement: %q): %v", dto.Purl, dto.Requirement, err)
			resolutions = append(resolutions, invalid(compHelper.PurlInfo{Purl: dto.Purl},
				compHelper.ComponentDTO{Purl: originalPurl}, originalRequirement, "Invalid Purl"))
			continue
		}
		if len(version) > 0 {
			dto.Requirement = version
			dto.Purl = strings.Replace(dto.Purl, "@"+version, "", 1)
		}
		info.Purl = dto.Purl

		resolutions = append(resolutions, Resolution{Component: compHelper.Component{
			PurlInfo:            info,
			OriginalPurl:        originalPurl,
			OriginalRequirement: originalRequirement,
			Requirement:         dto.Requirement,
			Status:              domain.ComponentStatus{StatusCode: domain.Success},
		}})
	}
	return resolutions
}

// invalid builds the rejected-input result for a purl that never reached a
// database lookup.
func invalid(info compHelper.PurlInfo, dto compHelper.ComponentDTO, originalRequirement, message string) Resolution {
	return Resolution{Component: compHelper.Component{
		PurlInfo:            info,
		OriginalPurl:        dto.Purl,
		OriginalRequirement: originalRequirement,
		Requirement:         originalRequirement,
		Status:              domain.ComponentStatus{Message: message, StatusCode: domain.InvalidPurl},
	}}
}

// purlInfo builds the descriptive purl fields for a versionless purl.
func purlInfo(s *zap.SugaredLogger, purl string) (compHelper.PurlInfo, error) {
	info, _, err := purlInfoWithVersion(s, purl)
	return info, err
}

// purlInfoWithVersion is the port of the helper's unexported buildPurlInfo: it
// decomposes a purl into the descriptive fields the response carries, and returns
// any version the purl itself declared.
func purlInfoWithVersion(s *zap.SugaredLogger, purl string) (compHelper.PurlInfo, string, error) {
	packageURL, err := purlhelper.PurlFromString(purl)
	if err != nil {
		return compHelper.PurlInfo{}, "", err
	}
	componentName, err := compHelper.ComponentNameFromString(purl)
	if err != nil {
		return compHelper.PurlInfo{}, packageURL.Version, err
	}
	projectURL, err := purlhelper.ProjectUrl(componentName, packageURL.Type)
	if err != nil {
		s.Warnf("Failed to derive project URL for PURL %q: %v. URL will be empty.", purl, err)
		projectURL = ""
	}
	qualifiers := make(map[string]string, len(packageURL.Qualifiers))
	for _, q := range packageURL.Qualifiers {
		qualifiers[q.Key] = q.Value
	}
	return compHelper.PurlInfo{
		Purl:           purl,
		Name:           componentName,
		URL:            projectURL,
		PurlType:       packageURL.Type,
		PurlName:       packageURL.Name,
		PurlNamespace:  packageURL.Namespace,
		PurlQualifiers: qualifiers,
		PurlSubpath:    packageURL.Subpath,
	}, packageURL.Version, nil
}
