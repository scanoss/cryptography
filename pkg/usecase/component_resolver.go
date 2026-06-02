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

// Package usecase centralises requirement resolution through the shared
// go-component-helper, so every endpoint resolves a `requirement` to concrete
// version(s) the same way, against the same SCANOSS knowledge base.
package usecase

import (
	"context"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	"github.com/scanoss/go-component-helper/componenthelper"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
)

// componentResolverMaxWorkers caps the concurrency the component helper uses when
// resolving version requirements for a batch of components.
const componentResolverMaxWorkers = 5

// sourceFallbackStatus flags a result that was obtained by re-querying the component's
// source-code purl after the original purl returned no cryptographic information. It is not
// a domain error code: it surfaces as a per-component info_code so the caller knows the data
// comes from the upstream source.
const sourceFallbackStatus status.StatusCode = "WARNING"

// sourceFallbackMessage builds the info_message for a result recovered from the source-code
// purl, including the full source purl in parentheses for traceability.
func sourceFallbackMessage(sourcePurl string) string {
	return fmt.Sprintf("Showing results from the source code purl (%s)", sourcePurl)
}

// sourcePurlForFallback returns the source-code purl name/type to retry a crypto lookup against,
// when the component helper linked a usable source purl (populated only on a successful
// resolution that has a source-mine entry in the projects table). ok is false otherwise.
func sourcePurlForFallback(c componenthelper.Component) (name, purlType string, ok bool) {
	if c.SourcePurl != nil && c.SourcePurl.Status.StatusCode == status.Success &&
		c.SourcePurl.Name != "" && c.SourcePurl.PurlType != "" {
		return c.SourcePurl.Name, c.SourcePurl.PurlType, true
	}
	return "", "", false
}

// resolveComponentVersions resolves the version requirement of every input component
// through the shared go-component-helper, which queries the same knowledge base
// (all_urls/versions/mines) this service uses. It returns one resolved Component per
// input, in the SAME order: the helper processes components concurrently and does not
// preserve order, so results are matched back to their inputs by (purl, requirement).
func resolveComponentVersions(ctx context.Context, s *zap.SugaredLogger, db *sqlx.DB, components []dtos.ComponentDTO) []componenthelper.Component {
	input := make([]componenthelper.ComponentDTO, len(components))
	keys := make([]string, len(components))
	for i, c := range components {
		req := c.Requirement
		// Local ("file:") dependencies have no resolvable upstream version: treat as "latest".
		if strings.HasPrefix(req, "file:") {
			req = ""
		}
		input[i] = componenthelper.ComponentDTO{Purl: c.Purl, Requirement: req}
		keys[i] = componentResolverKey(c.Purl, req)
	}

	resolved := componenthelper.GetComponentsVersion(componenthelper.ComponentVersionCfg{
		MaxWorkers: componentResolverMaxWorkers,
		Ctx:        ctx,
		S:          s,
		DB:         db,
		Input:      input,
	})

	byKey := make(map[string]componenthelper.Component, len(resolved))
	for _, r := range resolved {
		byKey[componentResolverKey(r.OriginalPurl, r.OriginalRequirement)] = r
	}

	ordered := make([]componenthelper.Component, len(components))
	for i, k := range keys {
		if r, ok := byKey[k]; ok {
			ordered[i] = r
		} else {
			// Defensive: the helper returns one result per input, so this should not happen.
			// Log it instead of silently emitting a zero-value component (treated as not found downstream).
			s.Warnf("Component helper returned no result for purl %q (requirement %q); treating as not found", components[i].Purl, components[i].Requirement)
		}
	}
	return ordered
}

// componentResolverKey builds the lookup key used to realign concurrent helper results
// with their original inputs. The helper echoes the purl/requirement it was given back
// as OriginalPurl/OriginalRequirement, so the same pair reproduces the key.
func componentResolverKey(purl, requirement string) string {
	return purl + "\x00" + requirement
}

// isWildcardRequirement reports whether a range requirement is a wildcard such as "*", "v*"
// or an operator-prefixed form like ">v*" / ">=v*". semver accepts all of these as match-all,
// so the range endpoints reject them: a range query needs a real version bound.
func isWildcardRequirement(requirement string) bool {
	for _, part := range strings.Split(requirement, ",") {
		norm := strings.TrimLeft(strings.TrimSpace(part), "<>=~^ ")
		if norm == "*" || strings.HasPrefix(norm, "v*") {
			return true
		}
	}
	return false
}

// filterUrlsInRange keeps the URLs whose semantic version satisfies the requirement
// constraint (and whose purl type matches, when provided). It replaces the range filtering
// previously embedded in AllUrlsModel.GetUrlsByPurlNameTypeInRange, operating on an
// already-fetched URL set so version resolution stays in the component helper / model layer.
func filterUrlsInRange(urls []models.AllURL, purlType, requirement string) ([]models.AllURL, error) {
	// Reject empty and wildcard requirements: a range query needs an explicit constraint.
	// (semver accepts "*", "v*" and even ">v*"/">=v*" as match-all, so they are all caught here.)
	if requirement == "" || isWildcardRequirement(requirement) {
		return nil, fmt.Errorf("invalid range requirement '%s'", requirement)
	}
	constraint, err := semver.NewConstraint(requirement)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze range '%s': %w", requirement, err)
	}
	var filtered []models.AllURL
	for _, u := range urls {
		// When a type is requested, only keep URLs of that exact type (drop empty/other types).
		if purlType != "" && u.PurlType != purlType {
			continue
		}
		if u.SemVer == "" {
			continue
		}
		v, err := semver.NewVersion(u.SemVer)
		if err != nil {
			continue
		}
		if constraint.Check(v) {
			filtered = append(filtered, u)
		}
	}
	return filtered, nil
}
