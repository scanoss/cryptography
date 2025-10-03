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
	"scanoss.com/cryptography/pkg/handler"
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
			got := handler.buildComponentDTO(tt.purl, tt.requirement)
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
			got, err := handler.convertComponentsRequestToComponentDTO(tt.request)
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
		wantErr bool
	}{
		{
			name:    "Valid component",
			request: &common.ComponentRequest{Purl: "pkg:github/scanoss/engine", Requirement: "v5.4.5"},
			wantErr: false,
		},
		{
			name:    "Component with PURL version",
			request: &common.ComponentRequest{Purl: "pkg:github/scanoss/engine@v5.4.5", Requirement: ""},
			wantErr: false,
		},
		{
			name:    "Empty PURL",
			request: &common.ComponentRequest{Purl: "", Requirement: "v5.4.5"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateComponentRequest(tt.request)
			if (err != nil) && !tt.wantErr {
				t.Errorf("validateComponentRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_convertCryptoOutputToComponents(t *testing.T) {
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
			got, err := handler.convertCryptoOutputToComponents(s, tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertCryptoOutputToComponents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got.Components) != len(tt.want.Components) {
					t.Errorf("convertCryptoOutputToComponents() len = %v, want %v", len(got.Components), len(tt.want.Components))
					return
				}
				for i, component := range got.Components {
					if component.Purl != tt.want.Components[i].Purl {
						t.Errorf("convertCryptoOutputToComponents().Components[%d].Purl = %v, want %v", i, component.Purl, tt.want.Components[i].Purl)
					}
					if component.Version != tt.want.Components[i].Version {
						t.Errorf("convertCryptoOutputToComponents().Components[%d].Version = %v, want %v", i, component.Version, tt.want.Components[i].Version)
					}
					if component.Requirement != tt.want.Components[i].Requirement {
						t.Errorf("convertCryptoOutputToComponents().Components[%d].Requirement = %v, want %v", i, component.Requirement, tt.want.Components[i].Requirement)
					}
					if len(component.Algorithms) != len(tt.want.Components[i].Algorithms) {
						t.Errorf("convertCryptoOutputToComponents().Components[%d].Algorithms len = %v, want %v", i, len(component.Algorithms), len(tt.want.Components[i].Algorithms))
						continue
					}
					for j, alg := range component.Algorithms {
						if alg.Algorithm != tt.want.Components[i].Algorithms[j].Algorithm {
							t.Errorf("convertCryptoOutputToComponents().Components[%d].Algorithms[%d].Algorithm = %v, want %v", i, j, alg.Algorithm, tt.want.Components[i].Algorithms[j].Algorithm)
						}
						if alg.Strength != tt.want.Components[i].Algorithms[j].Strength {
							t.Errorf("convertCryptoOutputToComponents().Components[%d].Algorithms[%d].Strength = %v, want %v", i, j, alg.Strength, tt.want.Components[i].Algorithms[j].Strength)
						}
					}
				}
			}
		})
	}
}

func Test_convertComponentsCryptoInRangeOutput(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := zlog.L.Sugar()

	tests := []struct {
		name    string
		output  dtos.CryptoInRangeOutput
		want    *pb.ComponentsAlgorithmsInRangeResponse
		wantErr bool
	}{
		{
			name: "Valid single component with algorithms and versions",
			output: dtos.CryptoInRangeOutput{
				Cryptography: []dtos.CryptoInRangeOutputItem{
					{
						Purl:     "pkg:github/scanoss/engine",
						Versions: []string{"v5.4.5", "v5.4.6"},
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "aes", Strength: "256"},
							{Algorithm: "rsa", Strength: "2048"},
						},
					},
				},
			},
			want: &pb.ComponentsAlgorithmsInRangeResponse{
				Components: []*pb.ComponentsAlgorithmsInRangeResponse_Component{
					{
						Purl:     "pkg:github/scanoss/engine",
						Versions: []string{"v5.4.5", "v5.4.6"},
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
			output: dtos.CryptoInRangeOutput{
				Cryptography: []dtos.CryptoInRangeOutputItem{
					{
						Purl:     "pkg:github/scanoss/engine",
						Versions: []string{"v5.4.5"},
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "aes", Strength: "256"},
						},
					},
					{
						Purl:     "pkg:github/scanoss/dependencies",
						Versions: []string{"v1.0.0", "v1.0.1"},
						Algorithms: []dtos.CryptoUsageItem{
							{Algorithm: "sha256", Strength: "256"},
						},
					},
				},
			},
			want: &pb.ComponentsAlgorithmsInRangeResponse{
				Components: []*pb.ComponentsAlgorithmsInRangeResponse_Component{
					{
						Purl:     "pkg:github/scanoss/engine",
						Versions: []string{"v5.4.5"},
						Algorithms: []*pb.Algorithm{
							{Algorithm: "aes", Strength: "256"},
						},
					},
					{
						Purl:     "pkg:github/scanoss/dependencies",
						Versions: []string{"v1.0.0", "v1.0.1"},
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
			output: dtos.CryptoInRangeOutput{
				Cryptography: []dtos.CryptoInRangeOutputItem{},
			},
			want: &pb.ComponentsAlgorithmsInRangeResponse{
				Components: []*pb.ComponentsAlgorithmsInRangeResponse_Component{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handler.convertComponentsCryptoInRangeOutput(s, tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertComponentsCryptoInRangeOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got.Components) != len(tt.want.Components) {
					t.Errorf("convertComponentsCryptoInRangeOutput() len = %v, want %v", len(got.Components), len(tt.want.Components))
					return
				}
				for i, component := range got.Components {
					if component.Purl != tt.want.Components[i].Purl {
						t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Purl = %v, want %v", i, component.Purl, tt.want.Components[i].Purl)
					}
					if len(component.Versions) != len(tt.want.Components[i].Versions) {
						t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Versions len = %v, want %v", i, len(component.Versions), len(tt.want.Components[i].Versions))
						continue
					}
					for j, version := range component.Versions {
						if version != tt.want.Components[i].Versions[j] {
							t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Versions[%d] = %v, want %v", i, j, version, tt.want.Components[i].Versions[j])
						}
					}
					if len(component.Algorithms) != len(tt.want.Components[i].Algorithms) {
						t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Algorithms len = %v, want %v", i, len(component.Algorithms), len(tt.want.Components[i].Algorithms))
						continue
					}
					for j, alg := range component.Algorithms {
						if alg.Algorithm != tt.want.Components[i].Algorithms[j].Algorithm {
							t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Algorithms[%d].Algorithm = %v, want %v", i, j, alg.Algorithm, tt.want.Components[i].Algorithms[j].Algorithm)
						}
						if alg.Strength != tt.want.Components[i].Algorithms[j].Strength {
							t.Errorf("convertComponentsCryptoInRangeOutput().Components[%d].Algorithms[%d].Strength = %v, want %v", i, j, alg.Strength, tt.want.Components[i].Algorithms[j].Strength)
						}
					}
				}
			}
		})
	}
}

func Test_convertToComponentsVersionInRangeOutput(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := zlog.L.Sugar()

	tests := []struct {
		name    string
		output  dtos.VersionsInRangeOutput
		want    *pb.ComponentsVersionsInRangeResponse
		wantErr bool
	}{
		{
			name: "Valid single component with versions",
			output: dtos.VersionsInRangeOutput{
				Versions: []dtos.VersionsInRangeUsingCryptoItem{
					{
						Purl:            "pkg:github/scanoss/engine",
						VersionsWith:    []string{"v5.4.5", "v5.4.6"},
						VersionsWithout: []string{"v5.4.0", "v5.3.0"},
					},
				},
			},
			want: &pb.ComponentsVersionsInRangeResponse{
				Components: []*pb.ComponentsVersionsInRangeResponse_Component{
					{
						Purl:            "pkg:github/scanoss/engine",
						VersionsWith:    []string{"v5.4.5", "v5.4.6"},
						VersionsWithout: []string{"v5.4.0", "v5.3.0"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple components",
			output: dtos.VersionsInRangeOutput{
				Versions: []dtos.VersionsInRangeUsingCryptoItem{
					{
						Purl:            "pkg:github/scanoss/engine",
						VersionsWith:    []string{"v5.4.5"},
						VersionsWithout: []string{"v5.4.0"},
					},
					{
						Purl:            "pkg:github/scanoss/dependencies",
						VersionsWith:    []string{"v1.0.0", "v1.0.1"},
						VersionsWithout: []string{},
					},
				},
			},
			want: &pb.ComponentsVersionsInRangeResponse{
				Components: []*pb.ComponentsVersionsInRangeResponse_Component{
					{
						Purl:            "pkg:github/scanoss/engine",
						VersionsWith:    []string{"v5.4.5"},
						VersionsWithout: []string{"v5.4.0"},
					},
					{
						Purl:            "pkg:github/scanoss/dependencies",
						VersionsWith:    []string{"v1.0.0", "v1.0.1"},
						VersionsWithout: []string{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Empty versions output",
			output: dtos.VersionsInRangeOutput{
				Versions: []dtos.VersionsInRangeUsingCryptoItem{},
			},
			want: &pb.ComponentsVersionsInRangeResponse{
				Components: []*pb.ComponentsVersionsInRangeResponse_Component{},
			},
			wantErr: true,
		},
		{
			name: "Component with empty version lists",
			output: dtos.VersionsInRangeOutput{
				Versions: []dtos.VersionsInRangeUsingCryptoItem{
					{
						Purl:            "pkg:github/scanoss/empty",
						VersionsWith:    []string{},
						VersionsWithout: []string{},
					},
				},
			},
			want: &pb.ComponentsVersionsInRangeResponse{
				Components: []*pb.ComponentsVersionsInRangeResponse_Component{
					{
						Purl:            "pkg:github/scanoss/empty",
						VersionsWith:    []string{},
						VersionsWithout: []string{},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handler.convertToComponentsVersionInRangeOutput(s, tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToComponentsVersionInRangeOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got.Components) != len(tt.want.Components) {
					t.Errorf("convertToComponentsVersionInRangeOutput() len = %v, want %v", len(got.Components), len(tt.want.Components))
					return
				}
				for i, component := range got.Components {
					if component.Purl != tt.want.Components[i].Purl {
						t.Errorf("convertToComponentsVersionInRangeOutput().Components[%d].Purl = %v, want %v", i, component.Purl, tt.want.Components[i].Purl)
					}
					if len(component.VersionsWith) != len(tt.want.Components[i].VersionsWith) {
						t.Errorf("convertToComponentsVersionInRangeOutput().Components[%d].VersionsWith len = %v, want %v", i, len(component.VersionsWith), len(tt.want.Components[i].VersionsWith))
						continue
					}
					for j, version := range component.VersionsWith {
						if version != tt.want.Components[i].VersionsWith[j] {
							t.Errorf("convertToComponentsVersionInRangeOutput().Components[%d].VersionsWith[%d] = %v, want %v", i, j, version, tt.want.Components[i].VersionsWith[j])
						}
					}
					if len(component.VersionsWithout) != len(tt.want.Components[i].VersionsWithout) {
						t.Errorf("convertToComponentsVersionInRangeOutput().Components[%d].VersionsWithout len = %v, want %v", i, len(component.VersionsWithout), len(tt.want.Components[i].VersionsWithout))
						continue
					}
					for j, version := range component.VersionsWithout {
						if version != tt.want.Components[i].VersionsWithout[j] {
							t.Errorf("convertToComponentsVersionInRangeOutput().Components[%d].VersionsWithout[%d] = %v, want %v", i, j, version, tt.want.Components[i].VersionsWithout[j])
						}
					}
				}
			}
		})
	}
}
