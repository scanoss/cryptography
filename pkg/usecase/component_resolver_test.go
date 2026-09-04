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
	"testing"

	"github.com/scanoss/go-component-helper/componenthelper"
	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"scanoss.com/cryptography/pkg/resolver"
)

func TestSourcePurlForFallback(t *testing.T) {
	tests := []struct {
		name      string
		component resolver.Resolution
		wantName  string
		wantType  string
		wantOK    bool
	}{
		{
			name:      "no source purl",
			component: resolver.Resolution{},
			wantOK:    false,
		},
		{
			name: "source purl resolved successfully",
			component: resolver.Resolution{Component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					PurlInfo: componenthelper.PurlInfo{Name: "jonschlinkert/word-wrap", PurlType: "github"},
					Status:   status.ComponentStatus{StatusCode: status.Success},
				},
			}},
			wantName: "jonschlinkert/word-wrap",
			wantType: "github",
			wantOK:   true,
		},
		{
			name: "source purl not found is not usable",
			component: resolver.Resolution{Component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					Status: status.ComponentStatus{StatusCode: status.ComponentNotFound},
				},
			}},
			wantOK: false,
		},
		{
			name: "source purl success but empty name is not usable",
			component: resolver.Resolution{Component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					PurlInfo: componenthelper.PurlInfo{PurlType: "github"},
					Status:   status.ComponentStatus{StatusCode: status.Success},
				},
			}},
			wantOK: false,
		},
		{
			name: "source purl success but empty purl type is not usable",
			component: resolver.Resolution{Component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					PurlInfo: componenthelper.PurlInfo{Name: "jonschlinkert/word-wrap"},
					Status:   status.ComponentStatus{StatusCode: status.Success},
				},
			}},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, purlType, ok := sourcePurlForFallback(tt.component)
			if ok != tt.wantOK {
				t.Fatalf("sourcePurlForFallback() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (name != tt.wantName || purlType != tt.wantType) {
				t.Errorf("sourcePurlForFallback() = (%q, %q), want (%q, %q)", name, purlType, tt.wantName, tt.wantType)
			}
		})
	}
}

// filterVersionsInRange replaces filterUrlsInRange: it works on the version set the
// resolver returns rather than on a set of mining all_urls rows.
func TestFilterVersionsInRange(t *testing.T) {
	versions := []string{"1.0.0", "1.10.0", "1.2.0", "2.0.0", "not-a-version"}

	tests := []struct {
		name        string
		versions    []string
		requirement string
		want        []string
		wantErr     bool
	}{
		{
			// Ordering is by precedence, not text: 1.2.0 comes before 1.10.0.
			name:     "range keeps matching versions in semver order",
			versions: versions, requirement: "<2.0.0",
			want: []string{"1.0.0", "1.2.0", "1.10.0"},
		},
		{
			name:     "unparseable versions are skipped",
			versions: []string{"not-a-version", "1.0.0"}, requirement: ">=1.0.0",
			want: []string{"1.0.0"},
		},
		{
			name:     "range matching nothing returns empty",
			versions: versions, requirement: ">9.0.0", want: nil,
		},
		// A range query needs a real bound: semver treats all of these as match-all,
		// which would silently return every version.
		{name: "empty requirement is rejected", versions: versions, requirement: "", wantErr: true},
		{name: "wildcard is rejected", versions: versions, requirement: "*", wantErr: true},
		{name: "v-wildcard is rejected", versions: versions, requirement: "v*", wantErr: true},
		{name: "operator-prefixed wildcard is rejected", versions: versions, requirement: ">=v*", wantErr: true},
		{name: "unparseable requirement is rejected", versions: versions, requirement: "not a range", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterVersionsInRange(tt.versions, tt.requirement)
			if (err != nil) != tt.wantErr {
				t.Fatalf("filterVersionsInRange error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("filterVersionsInRange = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("filterVersionsInRange = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestSortVersionStrings(t *testing.T) {
	versions := []string{"2.0.0", "1.10.0", "1.2.0", "trunk"}
	sortVersionStrings(versions)
	want := []string{"1.2.0", "1.10.0", "2.0.0", "trunk"}
	for i := range want {
		if versions[i] != want[i] {
			t.Fatalf("sortVersionStrings = %v, want %v", versions, want)
		}
	}
}
