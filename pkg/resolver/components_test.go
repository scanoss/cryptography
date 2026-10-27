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
	"testing"

	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
)

func TestSanitiseComponents(t *testing.T) {
	s := zap.NewNop().Sugar()

	t.Run("a version in the purl moves to the requirement", func(t *testing.T) {
		got := SanitiseComponents(s, []compHelper.ComponentDTO{{Purl: "pkg:npm/log4js@1.0.0", Requirement: ">=2"}})
		if len(got) != 1 {
			t.Fatalf("got %d results, want 1", len(got))
		}
		c := got[0]
		// The purl's own version wins over a supplied requirement, and the purl is
		// carried forward without it.
		if c.Requirement != "1.0.0" {
			t.Errorf("requirement = %q, want 1.0.0", c.Requirement)
		}
		if c.Purl != "pkg:npm/log4js" {
			t.Errorf("purl = %q, want pkg:npm/log4js", c.Purl)
		}
		if c.OriginalPurl != "pkg:npm/log4js@1.0.0" || c.OriginalRequirement != ">=2" {
			t.Errorf("original inputs not preserved: %+v", c)
		}
	})

	// Scoped npm packages are stored percent-encoded, so stripping the version must
	// not re-render the purl: pkg:npm/%40scope/name is not pkg:npm/@scope/name.
	t.Run("percent-encoding survives version stripping", func(t *testing.T) {
		got := SanitiseComponents(s, []compHelper.ComponentDTO{{Purl: "pkg:npm/%40scope/name@2.1.0"}})
		if len(got) != 1 {
			t.Fatalf("got %d results, want 1", len(got))
		}
		if got[0].Purl != "pkg:npm/%40scope/name" {
			t.Errorf("purl = %q, want pkg:npm/%%40scope/name", got[0].Purl)
		}
	})

	t.Run("bad input is rejected without a lookup", func(t *testing.T) {
		got := SanitiseComponents(s, []compHelper.ComponentDTO{{Purl: ""}, {Purl: "not-a-purl"}})
		if len(got) != 2 {
			t.Fatalf("got %d results, want 2", len(got))
		}
		for _, c := range got {
			if c.Status.StatusCode != domain.InvalidPurl {
				t.Errorf("status = %q, want INVALID_PURL", c.Status.StatusCode)
			}
		}
	})
}

// The endpoints read the source link off the embedded Component, the same field
// go-component-helper used to populate from the mining `projects` table.
func TestResolveComponentsPopulatesSourcePurl(t *testing.T) {
	r := newTestResolver(t)
	got := ResolveComponents(context.Background(), zap.NewNop().Sugar(), r,
		[]compHelper.ComponentDTO{{Purl: "pkg:npm/log4js"}, {Purl: "pkg:npm/orphan"}}, 2)
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}

	linked := got[0]
	if linked.PurlID != "uuid-npm" {
		t.Errorf("purl_id = %q, want uuid-npm", linked.PurlID)
	}
	if linked.SourcePurl == nil {
		t.Fatal("want the linked source purl to be populated")
	}
	if linked.SourcePurl.Purl != "pkg:github/log4js-node/log4js-node" {
		t.Errorf("source purl = %q", linked.SourcePurl.Purl)
	}
	if linked.SourcePurl.PurlType != "github" || linked.SourcePurl.Name == "" {
		t.Errorf("source purl is missing the fields the fallback reads: %+v", linked.SourcePurl)
	}
	if linked.SourcePurl.Status.StatusCode != domain.Success {
		t.Errorf("source status = %q, want SUCCESS", linked.SourcePurl.Status.StatusCode)
	}
	if linked.SourcePurlID != "uuid-github" {
		t.Errorf("source purl_id = %q, want uuid-github", linked.SourcePurlID)
	}

	if got[1].SourcePurl != nil {
		t.Errorf("a component with no source link must report none, got %+v", got[1].SourcePurl)
	}
}

func TestResolveComponentsReportsUnknownComponents(t *testing.T) {
	r := newTestResolver(t)
	got := ResolveComponents(context.Background(), zap.NewNop().Sugar(), r,
		[]compHelper.ComponentDTO{{Purl: "pkg:npm/does-not-exist"}}, 1)
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if got[0].Status.StatusCode != domain.ComponentNotFound {
		t.Errorf("status = %q, want COMPONENT_NOT_FOUND", got[0].Status.StatusCode)
	}
}
