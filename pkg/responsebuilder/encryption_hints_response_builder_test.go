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

const hintsOKMessage = "Encryption's hints retrieved successfully."

type encryptionHintsCase struct {
	name  string
	input domain.HintsOutput
}

func encryptionHintsFixtures() []encryptionHintsCase {
	aesDetection := domain.ECDetectedItem{
		ID:          "1",
		Name:        "AES",
		Purl:        "pkg:crypto/aes",
		Description: "AES encryption",
		Category:    "symmetric",
		URL:         "https://example.com/aes",
	}
	rsaDetection := domain.ECDetectedItem{
		ID:          "2",
		Name:        "RSA",
		Purl:        "pkg:crypto/rsa",
		Description: "RSA encryption",
		Category:    "asymmetric",
		URL:         "https://example.com/rsa",
	}

	return []encryptionHintsCase{
		{
			name: "one_component_with_hints",
			input: domain.HintsOutput{
				Hints: []domain.HintsOutputItem{{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: ">=v5.4.0",
					Detections:  []domain.ECDetectedItem{aesDetection},
					Status:      status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
		{
			name: "two_components_mixed",
			input: domain.HintsOutput{
				Hints: []domain.HintsOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: ">=v5.4.0",
						Detections:  []domain.ECDetectedItem{aesDetection},
						Status:      status.ComponentStatus{StatusCode: status.Success},
					},
					{
						Purl:        "pkg:npm/react",
						Version:     "18.0.0",
						Requirement: "^18.0.0",
						Status:      status.ComponentStatus{Message: "No hints found", StatusCode: status.ComponentWithoutInfo},
					},
				},
			},
		},
		{
			name: "multiple_hints",
			input: domain.HintsOutput{
				Hints: []domain.HintsOutputItem{{
					Purl:        "pkg:maven/org.apache/commons",
					Version:     "3.0.0",
					Requirement: "*",
					Detections:  []domain.ECDetectedItem{aesDetection, rsaDetection},
					Status:      status.ComponentStatus{StatusCode: status.Success},
				}},
			},
		},
	}
}

func hintsFromDetections(dets ...domain.ECDetectedItem) []*cryptographyv2.Hint {
	out := make([]*cryptographyv2.Hint, 0, len(dets))
	for _, d := range dets {
		out = append(out, &cryptographyv2.Hint{
			Id: d.ID, Name: d.Name, Purl: d.Purl, Description: d.Description, Category: d.Category, Url: d.URL,
		})
	}
	return out
}

func TestToHintsResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}
	rsa := domain.ECDetectedItem{ID: "2", Name: "RSA", Purl: "pkg:crypto/rsa", Description: "RSA encryption", Category: "asymmetric", URL: "https://example.com/rsa"}

	wants := map[string]*cryptographyv2.HintsResponse{
		"one_component_with_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Purls: []*cryptographyv2.HintsResponse_Purls{{
				Purl:    "pkg:github/scanoss/engine",
				Version: "v5.4.5",
				Hints:   hintsFromDetections(aes),
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Purls: []*cryptographyv2.HintsResponse_Purls{
				{
					Purl:    "pkg:github/scanoss/engine",
					Version: "v5.4.5",
					Hints:   hintsFromDetections(aes),
				},
				{
					Purl:        "pkg:npm/react",
					Version:     "18.0.0",
					Hints:       []*cryptographyv2.Hint{},
					InfoMessage: ptr("No hints found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Purls: []*cryptographyv2.HintsResponse_Purls{{
				Purl:    "pkg:maven/org.apache/commons",
				Version: "3.0.0",
				Hints:   hintsFromDetections(aes, rsa),
			}},
		},
	}

	for _, tc := range encryptionHintsFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToHintsResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestToComponentsEncryptionHintsResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}
	rsa := domain.ECDetectedItem{ID: "2", Name: "RSA", Purl: "pkg:crypto/rsa", Description: "RSA encryption", Category: "asymmetric", URL: "https://example.com/rsa"}

	wants := map[string]*cryptographyv2.ComponentsEncryptionHintsResponse{
		"one_component_with_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Components: []*cryptographyv2.ComponentHints{{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "v5.4.5",
				Requirement: ">=v5.4.0",
				Hints:       hintsFromDetections(aes),
			}},
		},
		"two_components_mixed": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Components: []*cryptographyv2.ComponentHints{
				{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: ">=v5.4.0",
					Hints:       hintsFromDetections(aes),
				},
				{
					Purl:        "pkg:npm/react",
					Version:     "18.0.0",
					Requirement: "^18.0.0",
					Hints:       []*cryptographyv2.Hint{},
					InfoMessage: ptr("No hints found"),
					InfoCode:    ptr(string(status.ComponentWithoutInfo)),
				},
			},
		},
		"multiple_hints": {
			Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
			Components: []*cryptographyv2.ComponentHints{{
				Purl:        "pkg:maven/org.apache/commons",
				Version:     "3.0.0",
				Requirement: "*",
				Hints:       hintsFromDetections(aes, rsa),
			}},
		},
	}

	for _, tc := range encryptionHintsFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToComponentsEncryptionHintsResponse(ctx, log, tc.input)
			require.NoError(t, err)
			assert.Equal(t, wants[tc.name], got)
		})
	}
}

func TestComponentEncryptionHintsResponse(t *testing.T) {
	ctx := context.Background()
	log := zap.NewNop().Sugar()

	aes := domain.ECDetectedItem{ID: "1", Name: "AES", Purl: "pkg:crypto/aes", Description: "AES encryption", Category: "symmetric", URL: "https://example.com/aes"}

	input := domain.HintsOutput{
		Hints: []domain.HintsOutputItem{{
			Purl:        "pkg:github/scanoss/engine",
			Version:     "v5.4.5",
			Requirement: ">=v5.4.0",
			Detections:  []domain.ECDetectedItem{aes},
			Status:      status.ComponentStatus{StatusCode: status.Success},
		}},
	}

	want := &cryptographyv2.ComponentEncryptionHintsResponse{
		Status: &commonv2.StatusResponse{Status: commonv2.StatusCode_SUCCESS, Message: hintsOKMessage},
		Component: &cryptographyv2.ComponentHints{
			Purl:        "pkg:github/scanoss/engine",
			Version:     "v5.4.5",
			Requirement: ">=v5.4.0",
			Hints:       hintsFromDetections(aes),
		},
	}

	got, err := ToComponentEncryptionHintsResponse(ctx, log, input)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
