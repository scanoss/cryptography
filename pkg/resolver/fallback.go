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
	"fmt"
	"strings"
)

// SourceFallbackStatus is the status code reported on a result that was
// recovered from the component's linked source purl rather than from the purl
// the caller asked for. It matches what scanoss.api emits so both services
// signal the fallback the same way, and it reaches the API response as
// info_code because the adapter forwards any non-SUCCESS status verbatim.
const SourceFallbackStatus = "WARNING"

// SourceFallbackMessage explains, in the response, which purl the data came from.
func SourceFallbackMessage(sourcePurl string) string {
	return fmt.Sprintf("No data found for the requested purl; showing results for the related source purl %s", sourcePurl)
}

// WithSourceFallback runs lookup for a purl and, when that yields nothing,
// retries against the component's linked source-code purl.
//
// Vulnerability data is indexed by purl string, so a package that shares its
// code with an upstream repository - pkg:npm/browser-mjml-table and
// pkg:github/mjmlio/mjml, say - has no rows of its own even though the source
// repository does. The fallback recovers those, and applyFallback marks the
// result so a caller can tell it apart from a direct hit.
//
// The source hop carries the caller's version requirement first: a semver range
// is meaningful across ecosystems, and an exact version the source also
// publishes resolves correctly. Only when that finds nothing AND the source sits
// in a different ecosystem does it retry without the requirement, because an
// exact version from one ecosystem (a Go pseudo-version) has no counterpart in
// another (a GitHub tag). Same-ecosystem fallbacks are never retried, so a
// genuine exact match stays authoritative.
func WithSourceFallback[T any](
	ctx context.Context,
	purl string,
	requirement string,
	sourceFor func(context.Context, string) *SourcePurl,
	lookup func(ctx context.Context, purl, requirement string) (T, error),
	hasData func(T) bool,
	applyFallback func(result T, sourcePurl string) T,
) (T, error) {
	result, err := lookup(ctx, purl, requirement)
	if err == nil && hasData(result) {
		return result, nil
	}
	if recovered, ok := RecoverFromSource(ctx, purl, requirement, sourceFor, lookup, hasData, applyFallback); ok {
		return recovered, nil
	}
	return result, err
}

// RecoverFromSource is the fallback on its own, for callers that already know
// their lookup came back empty and should not pay for running it again. It
// resolves the linked source purl and retries there, reporting whether it found
// anything.
func RecoverFromSource[T any](
	ctx context.Context,
	purl string,
	requirement string,
	sourceFor func(context.Context, string) *SourcePurl,
	lookup func(ctx context.Context, purl, requirement string) (T, error),
	hasData func(T) bool,
	applyFallback func(result T, sourcePurl string) T,
) (T, bool) {
	var zero T
	if sourceFor == nil {
		return zero, false
	}
	source := sourceFor(ctx, purl)
	if source == nil || source.Purl == purl {
		return zero, false
	}
	return sourceHop(ctx, purl, requirement, source, lookup, hasData, applyFallback)
}

// sourceHop retries the lookup against the source purl, with the requirement
// and then - only across ecosystems - without it. Reports whether it found data.
func sourceHop[T any](
	ctx context.Context,
	purl string,
	requirement string,
	source *SourcePurl,
	lookup func(ctx context.Context, purl, requirement string) (T, error),
	hasData func(T) bool,
	applyFallback func(result T, sourcePurl string) T,
) (T, bool) {
	if result, err := lookup(ctx, source.Purl, requirement); err == nil && hasData(result) {
		return applyFallback(result, source.Purl), true
	}
	if len(requirement) > 0 && crossEcosystem(purl, source) {
		if result, err := lookup(ctx, source.Purl, ""); err == nil && hasData(result) {
			return applyFallback(result, source.Purl), true
		}
	}
	var zero T
	return zero, false
}

// crossEcosystem reports whether the source purl belongs to a different purl
// type than the original. An unparseable original is treated as same-ecosystem,
// which is the conservative answer: no extra retry.
func crossEcosystem(purl string, source *SourcePurl) bool {
	id, err := ParseIdentity(purl)
	return err == nil && !strings.EqualFold(id.PurlType, source.PurlType)
}
