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

package service

import (
	"testing"

	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/dtos"
)

func Test_buildComponentDTO(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		requirement string
		want        dtos.ComponentDTO
	}{
		{
			name:        "Simple PURL without version",
			purl:        "pkg:github/scanoss/engine",
			requirement: "v5.4.5",
			want: dtos.ComponentDTO{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "v5.4.5",
				Requirement: "v5.4.5",
			},
		},
		{
			name:        "PURL with version separator",
			purl:        "pkg:github/scanoss/engine@v5.4.5",
			requirement: "",
			want: dtos.ComponentDTO{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "v5.4.5",
				Requirement: "v5.4.5",
			},
		},
		{
			name:        "PURL with version separator and requirement",
			purl:        "pkg:github/scanoss/engine@v5.4.5",
			requirement: "v6.0.0",
			want: dtos.ComponentDTO{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "v5.4.5",
				Requirement: "v5.4.5",
			},
		},
		{
			name:        "Empty requirement",
			purl:        "pkg:github/scanoss/engine",
			requirement: "",
			want: dtos.ComponentDTO{
				Purl:        "pkg:github/scanoss/engine",
				Version:     "",
				Requirement: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildComponentDTO(tt.purl, tt.requirement)
			if got.Purl != tt.want.Purl {
				t.Errorf("buildComponentDTO().Purl = %v, want %v", got.Purl, tt.want.Purl)
			}
			if got.Version != tt.want.Version {
				t.Errorf("buildComponentDTO().Version = %v, want %v", got.Version, tt.want.Version)
			}
			if got.Requirement != tt.want.Requirement {
				t.Errorf("buildComponentDTO().Requirement = %v, want %v", got.Requirement, tt.want.Requirement)
			}
		})
	}
}

func Test_convertComponentsRequestToComponentDTO(t *testing.T) {
	tests := []struct {
		name    string
		request *common.ComponentsRequest
		want    []dtos.ComponentDTO
		wantErr bool
	}{
		{
			name: "Valid single component",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
				},
			},
			want: []dtos.ComponentDTO{
				{Purl: "pkg:github/scanoss/engine", Version: "v5.4.5", Requirement: "v5.4.5"},
			},
			wantErr: false,
		},
		{
			name: "Valid multiple components",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{
					{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
					{Purl: "pkg:github/scanoss/dependencies", Requirement: "v1.0.0"},
				},
			},
			want: []dtos.ComponentDTO{
				{Purl: "pkg:github/scanoss/engine", Version: "v5.4.5", Requirement: "v5.4.5"},
				{Purl: "pkg:github/scanoss/dependencies", Version: "v1.0.0", Requirement: "v1.0.0"},
			},
			wantErr: false,
		},
		{
			name: "Empty components",
			request: &common.ComponentsRequest{
				Components: []*common.ComponentRequest{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Nil components",
			request: &common.ComponentsRequest{
				Components: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertComponentsRequestToComponentDTO(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertComponentsRequestToComponentDTO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("convertComponentsRequestToComponentDTO() len = %v, want %v", len(got), len(tt.want))
					return
				}
				for i, component := range got {
					if component.Purl != tt.want[i].Purl {
						t.Errorf("convertComponentsRequestToComponentDTO()[%d].Purl = %v, want %v", i, component.Purl, tt.want[i].Purl)
					}
					if component.Version != tt.want[i].Version {
						t.Errorf("convertComponentsRequestToComponentDTO()[%d].Version = %v, want %v", i, component.Version, tt.want[i].Version)
					}
					if component.Requirement != tt.want[i].Requirement {
						t.Errorf("convertComponentsRequestToComponentDTO()[%d].Requirement = %v, want %v", i, component.Requirement, tt.want[i].Requirement)
					}
				}
			}
		})
	}
}

func Test_convertComponentRequestToComponentDTO(t *testing.T) {
	tests := []struct {
		name    string
		request *common.ComponentRequest
		want    dtos.ComponentDTO
		wantErr bool
	}{
		{
			name:    "Valid component",
			request: &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			want:    dtos.ComponentDTO{Purl: "pkg:github/scanoss/engine", Version: "v5.4.5", Requirement: "v5.4.5"},
			wantErr: false,
		},
		{
			name:    "Component with PURL version",
			request: &common.ComponentRequest{Purl: "pkg:github/scanoss/engine@v5.4.5", Requirement: ""},
			want:    dtos.ComponentDTO{Purl: "pkg:github/scanoss/engine", Version: "v5.4.5", Requirement: "v5.4.5"},
			wantErr: false,
		},
		{
			name:    "Empty PURL",
			request: &common.ComponentRequest{Purl: "", Requirement: "v5.4.5"},
			want:    dtos.ComponentDTO{Purl: "", Version: "v5.4.5", Requirement: "v5.4.5"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertComponentRequestToComponentDTO(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertComponentRequestToComponentDTO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Purl != tt.want.Purl {
				t.Errorf("convertComponentRequestToComponentDTO().Purl = %v, want %v", got.Purl, tt.want.Purl)
			}
			if got.Version != tt.want.Version {
				t.Errorf("convertComponentRequestToComponentDTO().Version = %v, want %v", got.Version, tt.want.Version)
			}
			if got.Requirement != tt.want.Requirement {
				t.Errorf("convertComponentRequestToComponentDTO().Requirement = %v, want %v", got.Requirement, tt.want.Requirement)
			}
		})
	}
}

func Test_cryptoOutputToComponentsAlgorithmsResponse(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := zlog.L.Sugar()

	tests := []struct {
		name    string
		output  dtos.CryptoOutput
		want    *pb.ComponentsAlgorithmsResponse
		wantErr bool
	}{
		{
			name: "Valid single component with algorithms",
			output: dtos.CryptoOutput{
				Cryptography: []dtos.CryptoOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "aes", Strength: "256"},
							{Algorithm: "rsa", Strength: "2048"},
						},
					},
				},
			},
			want: &pb.ComponentsAlgorithmsResponse{
				Components: []*pb.ComponentAlgorithms{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms: []*pb.Algorithm{
							{Algorithm: "aes", Strength: "256"},
							{Algorithm: "rsa", Strength: "2048"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple components",
			output: dtos.CryptoOutput{
				Cryptography: []dtos.CryptoOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "aes", Strength: "256"},
						},
					},
					{
						Purl:        "pkg:github/scanoss/dependencies",
						Version:     "v1.0.0",
						Requirement: "v1.0.0",
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "sha256", Strength: "256"},
						},
					},
				},
			},
			want: &pb.ComponentsAlgorithmsResponse{
				Components: []*pb.ComponentAlgorithms{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms: []*pb.Algorithm{
							{Algorithm: "aes", Strength: "256"},
						},
					},
					{
						Purl:        "pkg:github/scanoss/dependencies",
						Version:     "v1.0.0",
						Requirement: "v1.0.0",
						Algorithms: []*pb.Algorithm{
							{Algorithm: "sha256", Strength: "256"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Empty crypto output",
			output: dtos.CryptoOutput{
				Cryptography: []dtos.CryptoOutputItem{},
			},
			want: &pb.ComponentsAlgorithmsResponse{
				Components: []*pb.ComponentAlgorithms{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cryptoOutputToComponentsAlgorithmsResponse(s, tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("cryptoOutputToComponentsAlgorithmsResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got.Components) != len(tt.want.Components) {
					t.Errorf("cryptoOutputToComponentsAlgorithmsResponse() len = %v, want %v", len(got.Components), len(tt.want.Components))
					return
				}
				for i, component := range got.Components {
					if component.Purl != tt.want.Components[i].Purl {
						t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Purl = %v, want %v", i, component.Purl, tt.want.Components[i].Purl)
					}
					if component.Version != tt.want.Components[i].Version {
						t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Version = %v, want %v", i, component.Version, tt.want.Components[i].Version)
					}
					if component.Requirement != tt.want.Components[i].Requirement {
						t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Requirement = %v, want %v", i, component.Requirement, tt.want.Components[i].Requirement)
					}
					if len(component.Algorithms) != len(tt.want.Components[i].Algorithms) {
						t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Algorithms len = %v, want %v", i, len(component.Algorithms), len(tt.want.Components[i].Algorithms))
						continue
					}
					for j, alg := range component.Algorithms {
						if alg.Algorithm != tt.want.Components[i].Algorithms[j].Algorithm {
							t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Algorithms[%d].Algorithm = %v, want %v", i, j, alg.Algorithm, tt.want.Components[i].Algorithms[j].Algorithm)
						}
						if alg.Strength != tt.want.Components[i].Algorithms[j].Strength {
							t.Errorf("cryptoOutputToComponentsAlgorithmsResponse().Components[%d].Algorithms[%d].Strength = %v, want %v", i, j, alg.Strength, tt.want.Components[i].Algorithms[j].Strength)
						}
					}
				}
			}
		})
	}
}

func Test_cryptoOutputToComponentAlgorithmsResponse(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := zlog.L.Sugar()

	tests := []struct {
		name    string
		output  dtos.CryptoOutput
		want    *pb.ComponentAlgorithmsResponse
		wantErr bool
	}{
		{
			name: "Valid single component with algorithms",
			output: dtos.CryptoOutput{
				Cryptography: []dtos.CryptoOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "aes", Strength: "256"},
							{Algorithm: "rsa", Strength: "2048"},
						},
					},
				},
			},
			want: &pb.ComponentAlgorithmsResponse{
				Component: &pb.ComponentAlgorithms{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: "v5.4.5",
					Algorithms: []*pb.Algorithm{
						{Algorithm: "aes", Strength: "256"},
						{Algorithm: "rsa", Strength: "2048"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Component with no algorithms",
			output: dtos.CryptoOutput{
				Cryptography: []dtos.CryptoOutputItem{
					{
						Purl:        "pkg:github/scanoss/engine",
						Version:     "v5.4.5",
						Requirement: "v5.4.5",
						Algorithms:  []dtos.CryptoUsageItem{},
					},
				},
			},
			want: &pb.ComponentAlgorithmsResponse{
				Component: &pb.ComponentAlgorithms{
					Purl:        "pkg:github/scanoss/engine",
					Version:     "v5.4.5",
					Requirement: "v5.4.5",
					Algorithms:  []*pb.Algorithm{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cryptoOutputToComponentAlgorithmsResponse(s, tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("cryptoOutputToComponentAlgorithmsResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Component.Purl != tt.want.Component.Purl {
					t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Purl = %v, want %v", got.Component.Purl, tt.want.Component.Purl)
				}
				if got.Component.Version != tt.want.Component.Version {
					t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Version = %v, want %v", got.Component.Version, tt.want.Component.Version)
				}
				if got.Component.Requirement != tt.want.Component.Requirement {
					t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Requirement = %v, want %v", got.Component.Requirement, tt.want.Component.Requirement)
				}
				if len(got.Component.Algorithms) != len(tt.want.Component.Algorithms) {
					t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Algorithms len = %v, want %v", len(got.Component.Algorithms), len(tt.want.Component.Algorithms))
					return
				}
				for i, alg := range got.Component.Algorithms {
					if alg.Algorithm != tt.want.Component.Algorithms[i].Algorithm {
						t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Algorithms[%d].Algorithm = %v, want %v", i, alg.Algorithm, tt.want.Component.Algorithms[i].Algorithm)
					}
					if alg.Strength != tt.want.Component.Algorithms[i].Strength {
						t.Errorf("cryptoOutputToComponentAlgorithmsResponse().Component.Algorithms[%d].Strength = %v, want %v", i, alg.Strength, tt.want.Component.Algorithms[i].Strength)
					}
				}
			}
		})
	}
}