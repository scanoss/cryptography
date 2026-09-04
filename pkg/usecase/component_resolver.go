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

// Package usecase centralises requirement resolution, so every endpoint resolves
// a `requirement` to concrete version(s) the same way, against the same serving
// knowledge base.
package usecase

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/resolver"
)

// componentResolverMaxWorkers caps the concurrency used when resolving version
// requirements for a batch of components.
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

// sourcePurlForFallback returns the source-code purl name/type to retry a crypto lookup
// against, when the component resolved to one. Mining derived this link from the `projects`
// table's source-mine columns; serving links it through `component.source_purl_id`.
// ok is false when there is no usable source.
func sourcePurlForFallback(c resolver.Resolution) (name, purlType string, ok bool) {
	if c.SourcePurl != nil && c.SourcePurl.Status.StatusCode == status.Success &&
		c.SourcePurl.Name != "" && c.SourcePurl.PurlType != "" {
		return c.SourcePurl.Name, c.SourcePurl.PurlType, true
	}
	return "", "", false
}

// resolveComponentVersions resolves the version requirement of every input component
// against the serving schema. It returns one Resolution per input, in the SAME order.
func resolveComponentVersions(ctx context.Context, s *zap.SugaredLogger, r *resolver.Resolver,
	components []dtos.ComponentDTO,
) []resolver.Resolution {
	input := make([]compHelper.ComponentDTO, 0, len(components))
	for _, c := range components {
		req := c.Requirement
		// Local ("file:") dependencies have no resolvable upstream version: treat as "latest".
		if strings.HasPrefix(req, "file:") {
			req = ""
		}
		input = append(input, compHelper.ComponentDTO{Purl: c.Purl, Requirement: req})
	}
	return resolver.ResolveComponents(ctx, s, r, input, componentResolverMaxWorkers)
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

// filterVersionsInRange keeps the versions satisfying the requirement constraint, sorted
// ascending by precedence.
//
// It replaces filterUrlsInRange, which filtered a set of mining `all_urls` rows. Serving
// gives the version set directly on the resolved component, so there is nothing to join
// through and no purl type to re-check: the resolution already pinned one component.
func filterVersionsInRange(versions []string, requirement string) ([]string, error) {
	// Reject empty and wildcard requirements: a range query needs an explicit constraint.
	// (semver accepts "*", "v*" and even ">v*"/">=v*" as match-all, so they are all caught here.)
	if requirement == "" || isWildcardRequirement(requirement) {
		return nil, fmt.Errorf("invalid range requirement '%s'", requirement)
	}
	constraint, err := semver.NewConstraint(requirement)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze range '%s': %w", requirement, err)
	}
	type parsed struct {
		raw string
		sv  *semver.Version
	}
	var kept []parsed
	for _, v := range versions {
		sv, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if constraint.Check(sv) {
			kept = append(kept, parsed{raw: v, sv: sv})
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].sv.LessThan(kept[j].sv) })
	out := make([]string, 0, len(kept))
	for _, k := range kept {
		out = append(out, k.raw)
	}
	return out, nil
}

// sortVersionStrings orders version strings by semver precedence, leaving
// unparseable ones at the end in lexical order. Used where a set of versions is
// collected from a map and the response needs a stable order.
func sortVersionStrings(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		a, errA := semver.NewVersion(versions[i])
		b, errB := semver.NewVersion(versions[j])
		switch {
		case errA == nil && errB == nil:
			return a.LessThan(b)
		case errA == nil:
			return true
		case errB == nil:
			return false
		default:
			return versions[i] < versions[j]
		}
	})
}
