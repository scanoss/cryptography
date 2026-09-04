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
	"testing"
)

// call records one lookup the fallback machinery made.
type call struct {
	purl        string
	requirement string
}

// stubLookup returns a lookup function serving `data` and recording every call.
func stubLookup(data map[call]string, calls *[]call) func(context.Context, string, string) (string, error) {
	return func(_ context.Context, purl, requirement string) (string, error) {
		*calls = append(*calls, call{purl, requirement})
		return data[call{purl, requirement}], nil
	}
}

func hasData(s string) bool { return s != "" }

func markFallback(s, sourcePurl string) string { return s + "|from:" + sourcePurl }

func sourceFor(source *SourcePurl) func(context.Context, string) *SourcePurl {
	return func(context.Context, string) *SourcePurl { return source }
}

func TestWithSourceFallbackKeepsDirectHit(t *testing.T) {
	var calls []call
	data := map[call]string{{"pkg:npm/pkg", "1.0.0"}: "direct"}
	source := &SourcePurl{Purl: "pkg:github/org/repo", PurlType: "github"}

	got, err := WithSourceFallback(context.Background(), "pkg:npm/pkg", "1.0.0",
		sourceFor(source), stubLookup(data, &calls), hasData, markFallback)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "direct" {
		t.Errorf("result = %q, want the unmarked direct hit", got)
	}
	if len(calls) != 1 {
		t.Errorf("made %d lookups, want 1: a direct hit must not consult the source", len(calls))
	}
}

func TestWithSourceFallbackRecoversFromSource(t *testing.T) {
	var calls []call
	// Nothing under the npm purl; the GitHub repository it was built from has it.
	data := map[call]string{{"pkg:github/org/repo", "1.0.0"}: "recovered"}
	source := &SourcePurl{Purl: "pkg:github/org/repo", PurlType: "github"}

	got, err := WithSourceFallback(context.Background(), "pkg:npm/pkg", "1.0.0",
		sourceFor(source), stubLookup(data, &calls), hasData, markFallback)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "recovered|from:pkg:github/org/repo" {
		t.Errorf("result = %q, want the source hit marked with its purl", got)
	}
}

// The requirement is carried to the source first, and only dropped when that finds
// nothing AND the source is in another ecosystem - an exact version from one
// ecosystem has no counterpart in another.
func TestSourceHopDropsRequirementOnlyAcrossEcosystems(t *testing.T) {
	tests := []struct {
		name      string
		purl      string
		source    *SourcePurl
		data      map[call]string
		want      string
		wantCalls []call
	}{
		{
			name:   "cross ecosystem retries without the requirement",
			purl:   "pkg:npm/pkg",
			source: &SourcePurl{Purl: "pkg:github/org/repo", PurlType: "github"},
			data:   map[call]string{{"pkg:github/org/repo", ""}: "latest"},
			want:   "latest|from:pkg:github/org/repo",
			wantCalls: []call{
				{"pkg:npm/pkg", "1.0.0"},
				{"pkg:github/org/repo", "1.0.0"},
				{"pkg:github/org/repo", ""},
			},
		},
		{
			// Same ecosystem: an exact version that the source does not have is a
			// genuine miss, so it stays a miss rather than silently becoming the latest.
			name:   "same ecosystem does not retry",
			purl:   "pkg:npm/pkg",
			source: &SourcePurl{Purl: "pkg:npm/other", PurlType: "npm"},
			data:   map[call]string{{"pkg:npm/other", ""}: "latest"},
			want:   "",
			wantCalls: []call{
				{"pkg:npm/pkg", "1.0.0"},
				{"pkg:npm/other", "1.0.0"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			got, _ := WithSourceFallback(context.Background(), tt.purl, "1.0.0",
				sourceFor(tt.source), stubLookup(tt.data, &calls), hasData, markFallback)
			if got != tt.want {
				t.Errorf("result = %q, want %q", got, tt.want)
			}
			if len(calls) != len(tt.wantCalls) {
				t.Fatalf("lookups = %v, want %v", calls, tt.wantCalls)
			}
			for i := range calls {
				if calls[i] != tt.wantCalls[i] {
					t.Errorf("lookup %d = %v, want %v", i, calls[i], tt.wantCalls[i])
				}
			}
		})
	}
}

func TestRecoverFromSourceSkipsPointlessHops(t *testing.T) {
	tests := []struct {
		name   string
		source *SourcePurl
	}{
		{"no source link", nil},
		// A component whose source link points back at itself would just repeat the
		// lookup that already came back empty.
		{"source is the purl itself", &SourcePurl{Purl: "pkg:npm/pkg", PurlType: "npm"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			_, ok := RecoverFromSource(context.Background(), "pkg:npm/pkg", "1.0.0",
				sourceFor(tt.source), stubLookup(nil, &calls), hasData, markFallback)
			if ok {
				t.Error("want no recovery")
			}
			if len(calls) != 0 {
				t.Errorf("made %d lookups, want 0", len(calls))
			}
		})
	}

	t.Run("nil sourceFor disables the fallback", func(t *testing.T) {
		var calls []call
		if _, ok := RecoverFromSource(context.Background(), "pkg:npm/pkg", "1.0.0",
			nil, stubLookup(nil, &calls), hasData, markFallback); ok {
			t.Error("want no recovery")
		}
	})
}

// A lookup that fails is not a miss: the fallback must not turn a broken query into
// a quietly successful "nothing found" for the original purl.
func TestWithSourceFallbackPropagatesLookupError(t *testing.T) {
	wantErr := errors.New("query failed")
	source := &SourcePurl{Purl: "pkg:github/org/repo", PurlType: "github"}
	failing := func(context.Context, string, string) (string, error) { return "", wantErr }

	_, err := WithSourceFallback(context.Background(), "pkg:npm/pkg", "1.0.0",
		sourceFor(source), failing, hasData, markFallback)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}
