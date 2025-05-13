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

package dtos

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
)

func TestParseCryptoInput(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()

	tests := []struct {
		name           string
		input          []byte
		expectedOutput CryptoInput
		expectedErr    bool
	}{
		{
			name: "Should_ParseSuccessfully_WhenPurlHasRequirement",
			input: []byte(
				`{ "purls": [ 
								{
									"purl": "pkg:github/pineappleea/pineapple-src",
									"requirement":">=0"
								}
							]
				}`),
			expectedOutput: CryptoInput{
				Purls: []CryptoInputItem{
					{
						Purl:        "pkg:github/pineappleea/pineapple-src",
						Requirement: ">=0",
					},
				},
			},
			expectedErr: false,
		},
		{
			name: "Should_ParseSuccessfully_WhenPurlHasNoRequirement",
			input: []byte(
				`{ "purls": [ 
								{
									"purl": "pkg:github/pineappleea/pineapple-src"
								}
							]
				}`),
			expectedOutput: CryptoInput{
				Purls: []CryptoInputItem{
					{
						Purl: "pkg:github/pineappleea/pineapple-src",
					},
				},
			},
			expectedErr: false,
		},
		{
			name:           "Should_ReturnError_WhenInputIsEmptyString",
			input:          []byte(""),
			expectedOutput: CryptoInput{},
			expectedErr:    true,
		},
		{
			name:           "Should_ReturnError_WhenInputContainsOnlyWhitespace",
			input:          []byte(" "),
			expectedOutput: CryptoInput{},
			expectedErr:    true,
		},
		{
			name:           "Should_ReturnError_WhenInputIsNull",
			input:          []byte("null"),
			expectedOutput: CryptoInput{},
			expectedErr:    false,
		},
		{
			name:           "Should_ReturnError_WhenInputIsInvalidJSON",
			input:          []byte("{this is not valid json}"),
			expectedOutput: CryptoInput{},
			expectedErr:    true,
		},
		{
			name:           "Should_ReturnError_WhenInputIsIncompleteJSON",
			input:          []byte("{\"Purls\": ["),
			expectedOutput: CryptoInput{},
			expectedErr:    true,
		},
		{
			name:           "Should_ReturnError_WhenFieldTypeIsWrong",
			input:          []byte("{\"Purls\": \"not an array\"}"),
			expectedOutput: CryptoInput{},
			expectedErr:    true,
		},
	}

	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {

			requestDto, err := ParseCryptoInput(s, test.input)
			if err == nil && test.expectedErr {
				t.Fatalf("an error was expected when parsing input json, %v", err)
			}
			require.Equal(t, test.expectedOutput, requestDto)
		})
	}
}
