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

package responsebuilder

import (
	"context"
	"testing"

	status "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"github.com/scanoss/papi/api/commonv2"
	"github.com/scanoss/papi/api/cryptographyv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/domain"
)

const versionsInRangeOKMessage = "Versions in range retrieved successfully."

type versionsInRangeCase struct {
	name  string
	input domain.VersionsInRangeOutput
}

func versionsInRangeFixtures() []versionsInRangeCase {
	return []versionsInRangeCase{
		{
			name: "one_component_with_versions",
			input: domain.VersionsInRangeOutput{
				Versions: []domain.VersionsInRangeUsingCryptoItem{{
					Purl:            "pkg:github/scanoss/engine",
					VersionsWith:    []string{"v5.4.6", "v5.4.7"},
					VersionsWithout: []string{"v5.4.5"},
					Status:          status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
		{
			name: "two_components_mixed",
			input: domain.VersionsInRangeOutput{
				Versions: []domain.VersionsInRangeUsingCryptoItem{
					{
						Purl:            "pkg:github/scanoss/engine",
						VersionsWith:    []string{"v5.4.6"},
						VersionsWithout: []string{"v5.4.5"},
						Status:          status.ComponentStatus{StatusCode: status.Success},
					},
					{
						Purl:            "pkg:npm/react",
						VersionsWith:    []string{},
						VersionsWithout: []string{"18.0.0"},
						Status:          status.ComponentStatus{Message: "No crypto found", StatusCode: status.ComponentWithoutInfo},
					},
				},
			},
		},
		{
			name: "all_versions_with_crypto",
			input: domain.VersionsInRangeOutput{
				Versions: []domain.VersionsInRangeUsingCryptoItem{{
					Purl:            "pkg:maven/org.apache/commons",
					VersionsWith:    []string{"3.0.0", "3.0.1", "3.0.2"},
					VersionsWithout: []string{},
					Status:          status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
	}
}

func TestToVersionsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	wants := map[string]*cryptographyv2.VersionsInRangeResponse{
		"one_component_with_versions": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Purls: []*cryptographyv2.VersionsInRangeResponse_Purl{{
				Purl:            "pkg:github/scanoss/engine",
				VersionsWith:    []string{"v5.4.6", "v5.4.7"},
				VersionsWithout: []string{"v5.4.5"},
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Purls: []*cryptographyv2.VersionsInRangeResponse_Purl{
				{
					Purl:            "pkg:github/scanoss/engine",
					VersionsWith:    []string{"v5.4.6"},
					VersionsWithout: []string{"v5.4.5"},
				},
				{
					Purl:            "pkg:npm/react",
					VersionsWith:    []string{},
					VersionsWithout: []string{"18.0.0"},
					InfoMessage:     ptr("No crypto found"),
					InfoCode:        ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"all_versions_with_crypto": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Purls: []*cryptographyv2.VersionsInRangeResponse_Purl{{
				Purl:            "pkg:maven/org.apache/commons",
				VersionsWith:    []string{"3.0.0", "3.0.1", "3.0.2"},
				VersionsWithout: []string{},
			}},
		},
	}

	for _, tc := range versionsInRangeFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToVersionsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestToComponentsVersionsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	wants := map[string]*cryptographyv2.ComponentsVersionsInRangeResponse{
		"one_component_with_versions": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsVersionsInRangeResponse_Component{{
				Purl:            "pkg:github/scanoss/engine",
				VersionsWith:    []string{"v5.4.6", "v5.4.7"},
				VersionsWithout: []string{"v5.4.5"},
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsVersionsInRangeResponse_Component{
				{
					Purl:            "pkg:github/scanoss/engine",
					VersionsWith:    []string{"v5.4.6"},
					VersionsWithout: []string{"v5.4.5"},
				},
				{
					Purl:            "pkg:npm/react",
					VersionsWith:    []string{},
					VersionsWithout: []string{"18.0.0"},
					InfoMessage:     ptr("No crypto found"),
					InfoCode:        ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"all_versions_with_crypto": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsVersionsInRangeResponse_Component{{
				Purl:            "pkg:maven/org.apache/commons",
				VersionsWith:    []string{"3.0.0", "3.0.1", "3.0.2"},
				VersionsWithout: []string{},
			}},
		},
	}

	for _, tc := range versionsInRangeFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentsVersionsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestComponentVersionsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	input := domain.VersionsInRangeOutput{
		Versions: []domain.VersionsInRangeUsingCryptoItem{{
			Purl:            "pkg:github/scanoss/engine",
			VersionsWith:    []string{"v5.4.6", "v5.4.7"},
			VersionsWithout: []string{"v5.4.5"},
			Status:          status.ComponentStatus{StatusCode: status.Success},
		}},
	}

	want := &cryptographyv2.ComponentVersionsInRangeResponse{
		Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: versionsInRangeOKMessage},
		Component: &cryptographyv2.ComponentVersionsInRangeResponse_Component{
			Purl:            "pkg:github/scanoss/engine",
			VersionsWith:    []string{"v5.4.6", "v5.4.7"},
			VersionsWithout: []string{"v5.4.5"},
		},
	}

	got, err := ToComponentVersionsInRangeResponse(ctx, log, input)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestComponentVersionsInRangeResponseNilInput(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	emptyInput := domain.VersionsInRangeOutput{Versions: nil}

	_, err := ToComponentVersionsInRangeResponse(ctx, log, emptyInput)
	assert.ErrorContains(t, err, "no versions found")
}
