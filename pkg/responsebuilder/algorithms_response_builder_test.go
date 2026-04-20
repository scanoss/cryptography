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

const algorithmsOKMessage = "Algorithms retrieved successfully."

// algorithmsFixtures returns the three scenarios shared between ToAlgorithmResponse
// and ToComponentsAlgorithmsResponse (same input, different expected output shapes).
type algorithmsCase struct {
	name  string
	input domain.CryptoOutput
}

func algorithmsFixtures() []algorithmsCase {
	return []algorithmsCase{
		{
			name: "one_component_with_algorithms",
			input: domain.CryptoOutput{
				Cryptography: []domain.CryptoOutputItem{{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: ">=v5.4.0",
					Algorithms:  []domain.CryptoUsageItem{{Algorithm: "SHA256", Strength: "256"}},
					Status:      status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
		{
			name: "two_components_mixed",
			input: domain.CryptoOutput{
				Cryptography: []domain.CryptoOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: ">=v5.4.0",
						Algorithms:  []domain.CryptoUsageItem{{Algorithm: "SHA256", Strength: "256"}},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
					{
						Purl:        "pkg:npm/react",
						Version:     "18.0.0",
						Requirement: "^18.0.0",
						Status:      status.ComponentStatus{Message: "No crypto found", StatusCode: status.ComponentWithoutInfo},
					},
				},
			},
		},
		{
			name: "multiple_algorithms",
			input: domain.CryptoOutput{
				Cryptography: []domain.CryptoOutputItem{{
					Purl:        "pkg:maven/org.apache/commons",
					Version:     "3.0.0",
					Requirement: "*",
					Algorithms: []domain.CryptoUsageItem{
						{Algorithm: "MD5", Strength: "128"},
						{Algorithm: "SHA256", Strength: "256"},
					},
					Status: status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
	}
}

func TestToAlgorithmResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	wants := map[string]*cryptographyv2.AlgorithmResponse{
		"one_component_with_algorithms": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Purls: []*cryptographyv2.AlgorithmResponse_Purls{{
				Purl:       "pkg:github/scanoss/engine",
				Version:    "v5.4.5",
				Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}},
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Purls: []*cryptographyv2.AlgorithmResponse_Purls{
				{
					Purl:       "pkg:github/scanoss/engine",
					Version:    "v5.4.5",
					Algorithms: []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}},
				},
				{
					Purl:        "pkg:npm/react",
					Version:     "18.0.0",
					Algorithms:  []*cryptographyv2.Algorithm{},
					InfoMessage: ptr("No crypto found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_algorithms": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Purls: []*cryptographyv2.AlgorithmResponse_Purls{{
				Purl:    "pkg:maven/org.apache/commons",
				Version: "3.0.0",
				Algorithms: []*cryptographyv2.Algorithm{
					{Algorithm: "MD5", Strength: "128"},
					{Algorithm: "SHA256", Strength: "256"},
				},
			}},
		},
	}

	for _, tc := range algorithmsFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToAlgorithmResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestToComponentsAlgorithmsResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	wants := map[string]*cryptographyv2.ComponentsAlgorithmsResponse{
		"one_component_with_algorithms": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Components: []*cryptographyv2.ComponentAlgorithms{{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "v5.4.5",
				Requirement: ">=v5.4.0",
				Algorithms:  []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}},
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Components: []*cryptographyv2.ComponentAlgorithms{
				{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: ">=v5.4.0",
					Algorithms:  []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}},
				},
				{
					Purl:        "pkg:npm/react",
					Version:     "18.0.0",
					Requirement: "^18.0.0",
					Algorithms:  []*cryptographyv2.Algorithm{},
					InfoMessage: ptr("No crypto found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_algorithms": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
			Components: []*cryptographyv2.ComponentAlgorithms{{
				Purl:        "pkg:maven/org.apache/commons",
				Version:     "3.0.0",
				Requirement: "*",
				Algorithms: []*cryptographyv2.Algorithm{
					{Algorithm: "MD5", Strength: "128"},
					{Algorithm: "SHA256", Strength: "256"},
				},
			}},
		},
	}

	for _, tc := range algorithmsFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentsAlgorithmsResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestComponentAlgorithmsResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	input := domain.CryptoOutput{
		Cryptography: []domain.CryptoOutputItem{{
			Purl:        "pkg:github/scanoss/engine",
			Version:     "v5.4.5",
			Requirement: ">=v5.4.0",
			Algorithms:  []domain.CryptoUsageItem{{Algorithm: "SHA256", Strength: "256"}},
			Status:      status.ComponentStatus{StatusCode: status.Success},
		}},
	}

	want := &cryptographyv2.ComponentAlgorithmsResponse{
		Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: algorithmsOKMessage},
		Component: &cryptographyv2.ComponentAlgorithms{
			Purl:        "pkg:github/scanoss/engine",
			Version:     "v5.4.5",
			Requirement: ">=v5.4.0",
			Algorithms:  []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}},
		},
	}

	got, err := ToComponentAlgorithmsResponse(ctx, log, input)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestAlgorithmsResponseNilInput(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	emptyInput := domain.CryptoOutput{Cryptography: nil}

	_, err := ToAlgorithmResponse(ctx, log, emptyInput)
	assert.ErrorContains(t, err, "no cryptography found")

	_, err = ToComponentsAlgorithmsResponse(ctx, log, emptyInput)
	assert.ErrorContains(t, err, "no cryptography found")

	_, err = ToComponentAlgorithmsResponse(ctx, log, emptyInput)
	assert.ErrorContains(t, err, "no cryptography found")
}
