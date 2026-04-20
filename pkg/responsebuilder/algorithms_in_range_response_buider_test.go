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

// ptr returns a pointer to v. Package-level helper shared across test files in this package.
func ptr[T any](v T) *T { return &v }

const inRangeOKMessage = "Algorithms in range retrieved successfully."

func TestInRangeResponseForMultipleComponents(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	tests := []struct {
		name  string
		input domain.CryptoInRangeOutput
		want  *cryptographyv2.ComponentsAlgorithmsInRangeResponse
	}{
		{
			name: "two_components_ok",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Requirement: ">v5.4.5",
						Versions:    []string{"v5.4.6", "v5.4.7", "v5.5.0"},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
					{
						Purl:        "pkg:github/scanoss/ldb",
						Requirement: ">v1.0.0",
						Versions:    []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms:  []domain.CryptoUsageItem{{Algorithm: "MD5", Strength: "16"}},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
				},
			},
			want: &cryptographyv2.ComponentsAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Components: []*cryptographyv2.ComponentsAlgorithmsInRangeResponse_Component{
					{
						Purl:       "pkg:github/scanoss/engine",
						Versions:   []string{"v5.4.6", "v5.4.7", "v5.5.0"},
						Algorithms: []*cryptographyv2.Algorithm{},
					},
					{
						Purl:       "pkg:github/scanoss/ldb",
						Versions:   []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "MD5", Strength: "16"}},
					},
				},
			},
		},
		{
			name: "one_malformed_purl",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{
					{
						Purl:        "pkg:githubscanossengine",
						Requirement: ">v5.4.5",
						Status: status.ComponentStatus{
							Message:    "Failed to parse 1 purl(s):pkg:githubscanossengine",
							StatusCode: status.InvalidPurl,
						},
					},
					{
						Purl:        "pkg:github/scanoss/ldb",
						Requirement: ">v1.0.0",
						Versions:    []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms:  []domain.CryptoUsageItem{{Algorithm: "MD5", Strength: "16"}},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
				},
			},
			want: &cryptographyv2.ComponentsAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Components: []*cryptographyv2.ComponentsAlgorithmsInRangeResponse_Component{
					{
						Purl:        "pkg:githubscanossengine",
						Algorithms:  []*cryptographyv2.Algorithm{},
						InfoMessage: ptr("Failed to parse 1 purl(s):pkg:githubscanossengine"),
						InfoCode:    ptr(string(status.InvalidPurl)),
					},
					{
						Purl:       "pkg:github/scanoss/ldb",
						Versions:   []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "MD5", Strength: "16"}},
					},
				},
			},
		},
		{
			name: "one_not_found_purl",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{
					{
						Purl:        "pkg:github/scanoss/engines",
						Requirement: ">v5.4.5",
						Status: status.ComponentStatus{
							Message:    "Can't find 1 purl(s):scanoss/engines",
							StatusCode: status.ComponentNotFound,
						},
					},
					{
						Purl:        "pkg:github/scanoss/ldb",
						Requirement: ">v1.0.0",
						Versions:    []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms:  []domain.CryptoUsageItem{{Algorithm: "MD5", Strength: "16"}},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
				},
			},
			want: &cryptographyv2.ComponentsAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Components: []*cryptographyv2.ComponentsAlgorithmsInRangeResponse_Component{
					{
						Purl:        "pkg:github/scanoss/engines",
						Algorithms:  []*cryptographyv2.Algorithm{},
						InfoMessage: ptr("Can't find 1 purl(s):scanoss/engines"),
						InfoCode:    ptr(string(status.ComponentNotFound)),
					},
					{
						Purl:       "pkg:github/scanoss/ldb",
						Versions:   []string{"v1.0.1", "v1.0.2", "v1.0.3"},
						Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "MD5", Strength: "16"}},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentsAlgorithmsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToAlgorithmsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	input := domain.CryptoInRangeOutput{
		Cryptography: []domain.CryptoInRangeOutputItem{{
			Purl:        "pkg:github/scanoss/engine",
			Requirement: ">v5.4.5",
			Versions:    []string{"v5.4.6", "v5.4.7"},
			Algorithms:  []domain.CryptoUsageItem{{Algorithm: "SHA256", Strength: "256"}},
			Status:      status.ComponentStatus{StatusCode: status.Success},
		}},
	}

	got, err := ToAlgorithmsInRangeResponse(ctx, log, input)
	require.NoError(t, err)
	assert.Equal(t, commonv2.StatusCode_SUCCESS, got.Status.Status)
	assert.Equal(t, inRangeOKMessage, got.Status.Message)
	require.Len(t, got.Purls, 1)
	assert.Equal(t, "pkg:github/scanoss/engine", got.Purls[0].Purl)
	assert.Equal(t, []string{"v5.4.6", "v5.4.7"}, got.Purls[0].Versions)
}

func TestInRangeResponseForSingleComponent(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	tests := []struct {
		name  string
		input domain.CryptoInRangeOutput
		want  *cryptographyv2.ComponentAlgorithmsInRangeResponse
	}{
		{
			name: "good_purl",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{{
					Purl:        "pkg:github/scanoss/ldb",
					Requirement: ">v1.0.0",
					Versions:    []string{"v1.0.1", "v1.0.2", "v1.0.3"},
					Algorithms:  []domain.CryptoUsageItem{{Algorithm: "MD5", Strength: "16"}},
					Status:      status.ComponentStatus{StatusCode: status.Success},
				}},
			},
			want: &cryptographyv2.ComponentAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Component: &cryptographyv2.ComponentAlgorithmsInRangeResponse_Component{
					Purl:       "pkg:github/scanoss/ldb",
					Versions:   []string{"v1.0.1", "v1.0.2", "v1.0.3"},
					Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "MD5", Strength: "16"}},
				},
			},
		},
		{
			name: "no_crypto",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{{
					Purl:        "pkg:github/scanoss/ldb",
					Requirement: ">v1.0.0",
					Status:      status.ComponentStatus{Message: "No crypto found", StatusCode: status.NoInfo},
				}},
			},
			want: &cryptographyv2.ComponentAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Component: &cryptographyv2.ComponentAlgorithmsInRangeResponse_Component{
					Purl:        "pkg:github/scanoss/ldb",
					Algorithms:  []*cryptographyv2.Algorithm{},
					InfoMessage: ptr("No crypto found"),
					InfoCode:    ptr(string(status.NoInfo)),
				},
			},
		},
		{
			name: "purl_not_found",
			input: domain.CryptoInRangeOutput{
				Cryptography: []domain.CryptoInRangeOutputItem{{
					Purl:        "pkg:github/scanoss/ldbo",
					Requirement: ">v1.0.0",
					Status:      status.ComponentStatus{Message: "purl not found", StatusCode: status.ComponentNotFound},
				}},
			},
			want: &cryptographyv2.ComponentAlgorithmsInRangeResponse{
				Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: inRangeOKMessage},
				Component: &cryptographyv2.ComponentAlgorithmsInRangeResponse_Component{
					Purl:        "pkg:github/scanoss/ldbo",
					Algorithms:  []*cryptographyv2.Algorithm{},
					InfoMessage: ptr("purl not found"),
					InfoCode:    ptr(string(status.ComponentNotFound)),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentAlgorithmsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
