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

const hintsInRangeOKMessage = "Hints in range retrieved successfully."

type hintsInRangeCase struct {
	name  string
	input domain.ECOutput
}

func hintsInRangeFixtures() []hintsInRangeCase {
	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}
	rsa := domain.ECDetectedItem{ID: "2", Name: "RSA", Purl: "pkg:crypto/rsa", Description: "RSA encryption", Category: "asymmetric", URL: "https://example.com/rsa"}

	return []hintsInRangeCase{
		{
			name: "one_component_with_hints",
			input: domain.ECOutput{
				Hints: []domain.ECOutputItem{{
					Purl:       "pkg:github/scanoss/engine",
					Versions:   []string{"v5.4.6", "v5.4.7"},
					Detections: []domain.ECDetectedItem{aes},
					Status:     status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
		{
			name: "two_components_mixed",
			input: domain.ECOutput{
				Hints: []domain.ECOutputItem{
					{
						Purl:       "pkg:github/scanoss/engine",
						Versions:   []string{"v5.4.6", "v5.4.7"},
						Detections: []domain.ECDetectedItem{aes},
						Status:     status.ComponentStatus{StatusCode: status.Success},
					},
					{
						Purl:     "pkg:npm/react",
						Versions: []string{},
						Status:   status.ComponentStatus{Message: "No hints found", StatusCode: status.ComponentWithoutInfo},
					},
				},
			},
		},
		{
			name: "multiple_hints",
			input: domain.ECOutput{
				Hints: []domain.ECOutputItem{{
					Purl:       "pkg:maven/org.apache/commons",
					Versions:   []string{"3.0.0", "3.0.1"},
					Detections: []domain.ECDetectedItem{aes, rsa},
					Status:     status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
	}
}

func TestToHintsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}
	rsa := domain.ECDetectedItem{ID: "2", Name: "RSA", Purl: "pkg:crypto/rsa", Description: "RSA encryption", Category: "asymmetric", URL: "https://example.com/rsa"}

	wants := map[string]*cryptographyv2.HintsInRangeResponse{
		"one_component_with_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Purls: []*cryptographyv2.HintsInRangeResponse_Purl{{
				Purl:     "pkg:github/scanoss/engine",
				Versions: []string{"v5.4.6", "v5.4.7"},
				Hints:    hintsFromDetections(aes),
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Purls: []*cryptographyv2.HintsInRangeResponse_Purl{
				{
					Purl:     "pkg:github/scanoss/engine",
					Versions: []string{"v5.4.6", "v5.4.7"},
					Hints:    hintsFromDetections(aes),
				},
				{
					Purl:        "pkg:npm/react",
					Versions:    []string{},
					Hints:       []*cryptographyv2.Hint{},
					InfoMessage: ptr("No hints found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Purls: []*cryptographyv2.HintsInRangeResponse_Purl{{
				Purl:     "pkg:maven/org.apache/commons",
				Versions: []string{"3.0.0", "3.0.1"},
				Hints:    hintsFromDetections(aes, rsa),
			}},
		},
	}

	for _, tc := range hintsInRangeFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToHintsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestToComponentsHintsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}
	rsa := domain.ECDetectedItem{ID: "2", Name: "RSA", Purl: "pkg:crypto/rsa", Description: "RSA encryption", Category: "asymmetric", URL: "https://example.com/rsa"}

	wants := map[string]*cryptographyv2.ComponentsHintsInRangeResponse{
		"one_component_with_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsHintsInRangeResponse_Component{{
				Purl:     "pkg:github/scanoss/engine",
				Versions: []string{"v5.4.6", "v5.4.7"},
				Hints:    hintsFromDetections(aes),
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsHintsInRangeResponse_Component{
				{
					Purl:     "pkg:github/scanoss/engine",
					Versions: []string{"v5.4.6", "v5.4.7"},
					Hints:    hintsFromDetections(aes),
				},
				{
					Purl:        "pkg:npm/react",
					Versions:    []string{},
					Hints:       []*cryptographyv2.Hint{},
					InfoMessage: ptr("No hints found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
			Components: []*cryptographyv2.ComponentsHintsInRangeResponse_Component{{
				Purl:     "pkg:maven/org.apache/commons",
				Versions: []string{"3.0.0", "3.0.1"},
				Hints:    hintsFromDetections(aes, rsa),
			}},
		},
	}

	for _, tc := range hintsInRangeFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentsHintsInRangeResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestComponentHintsInRangeResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}

	input := domain.ECOutput{
		Hints: []domain.ECOutputItem{{
			Purl:       "pkg:github/scanoss/engine",
			Versions:   []string{"v5.4.6", "v5.4.7"},
			Detections: []domain.ECDetectedItem{aes},
			Status:     status.ComponentStatus{StatusCode: status.Success},
		}},
	}

	want := &cryptographyv2.ComponentHintsInRangeResponse{
		Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsInRangeOKMessage},
		Component: &cryptographyv2.ComponentHintsInRangeResponse_Component{
			Purl:     "pkg:github/scanoss/engine",
			Versions: []string{"v5.4.6", "v5.4.7"},
			Hints:    hintsFromDetections(aes),
		},
	}

	got, err := ToComponentHintsInRangeResponse(ctx, log, input)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
