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
)

func TestSourcePurlForFallback(t *testing.T) {
	tests := []struct {
		name      string
		component componenthelper.Component
		wantName  string
		wantType  string
		wantOK    bool
	}{
		{
			name:      "no source purl",
			component: componenthelper.Component{},
			wantOK:    false,
		},
		{
			name: "source purl resolved successfully",
			component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					PurlInfo: componenthelper.PurlInfo{Name: "jonschlinkert/word-wrap", PurlType: "github"},
					Status:   status.ComponentStatus{StatusCode: status.Success},
				},
			},
			wantName: "jonschlinkert/word-wrap",
			wantType: "github",
			wantOK:   true,
		},
		{
			name: "source purl not found is not usable",
			component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					Status: status.ComponentStatus{StatusCode: status.ComponentNotFound},
				},
			},
			wantOK: false,
		},
		{
			name: "source purl success but empty name is not usable",
			component: componenthelper.Component{
				SourcePurl: &componenthelper.SourcePurl{
					PurlInfo: componenthelper.PurlInfo{PurlType: "github"},
					Status:   status.ComponentStatus{StatusCode: status.Success},
				},
			},
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
