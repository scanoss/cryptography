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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	myconfig "scanoss.com/cryptography/pkg/config"
)

func TestNewRulesetDownload(t *testing.T) {
	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = "/tmp/rulesets"

	usecase := NewRulesetDownload(config)
	if usecase == nil {
		t.Error("NewRulesetDownload() returned nil")
	}
	if usecase.config == nil {
		t.Error("NewRulesetDownload() config is nil")
	}
	if usecase.config.Rulesets.StoragePath != "/tmp/rulesets" {
		t.Errorf("Expected storage path '/tmp/rulesets', got '%s'", usecase.config.Rulesets.StoragePath)
	}
}

func TestRulesetDownloadUseCase_DownloadRuleset(t *testing.T) {
	// Initialize logger
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	// Get the project root directory (assuming tests run from project root or pkg/usecase)
	projectRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get project root: %v", err)
	}
	testStoragePath := filepath.Join(projectRoot, "test-support", "rulesets")

	// Verify test data exists
	if _, err := os.Stat(testStoragePath); os.IsNotExist(err) {
		t.Skipf("Test data not found at %s, skipping tests", testStoragePath)
	}

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = testStoragePath

	usecase := NewRulesetDownload(config)
	ctx := context.Background()
	s := zlog.S

	tests := []struct {
		name           string
		rulesetName    string
		version        string
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result RulesetDownloadOutput)
	}{
		{
			name:        "download specific version - dca v1.0.1",
			rulesetName: "dca",
			version:     "v1.0.1",
			expectError: false,
			validateResult: func(t *testing.T, result RulesetDownloadOutput) {
				if result.Metadata.Name != "dca" {
					t.Errorf("Expected name 'dca', got '%s'", result.Metadata.Name)
				}
				if result.Metadata.Version != "v1.0.1" {
					t.Errorf("Expected version 'v1.0.1', got '%s'", result.Metadata.Version)
				}
				if len(result.TarballData) == 0 {
					t.Error("Expected non-empty tarball data")
				}
				if result.Metadata.ChecksumSHA256 == "" {
					t.Error("Expected non-empty checksum")
				}
			},
		},
		{
			name:        "download specific version - dca v1.0.0",
			rulesetName: "dca",
			version:     "v1.0.0",
			expectError: false,
			validateResult: func(t *testing.T, result RulesetDownloadOutput) {
				if result.Metadata.Name != "dca" {
					t.Errorf("Expected name 'dca', got '%s'", result.Metadata.Name)
				}
				if result.Metadata.Version != "v1.0.0" {
					t.Errorf("Expected version 'v1.0.0', got '%s'", result.Metadata.Version)
				}
				if len(result.TarballData) == 0 {
					t.Error("Expected non-empty tarball data")
				}
			},
		},
		{
			name:        "download latest version",
			rulesetName: "dca",
			version:     "latest",
			expectError: false,
			validateResult: func(t *testing.T, result RulesetDownloadOutput) {
				if result.Metadata.Name != "dca" {
					t.Errorf("Expected name 'dca', got '%s'", result.Metadata.Name)
				}
				// The latest symlink should point to v1.0.1
				if result.Metadata.Version != "v1.0.1" {
					t.Errorf("Expected latest version to be 'v1.0.1', got '%s'", result.Metadata.Version)
				}
				if len(result.TarballData) == 0 {
					t.Error("Expected non-empty tarball data")
				}
			},
		},
		{
			name:          "ruleset not found",
			rulesetName:   "nonexistent-ruleset",
			version:       "v1.0.0",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "version not found",
			rulesetName:   "dca",
			version:       "v99.99.99",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "empty ruleset name",
			rulesetName:   "",
			version:       "v1.0.0",
			expectError:   true,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := usecase.DownloadRuleset(ctx, s, tt.rulesetName, tt.version)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorContains)
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
					return
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

func TestRulesetDownloadUseCase_resolveVersion(t *testing.T) {
	// Initialize logger
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	projectRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get project root: %v", err)
	}
	testStoragePath := filepath.Join(projectRoot, "test-support", "rulesets")

	if _, err := os.Stat(testStoragePath); os.IsNotExist(err) {
		t.Skipf("Test data not found at %s, skipping tests", testStoragePath)
	}

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = testStoragePath

	usecase := NewRulesetDownload(config)
	s := zlog.S

	tests := []struct {
		name          string
		rulesetName   string
		version       string
		expectError   bool
		errorContains string
	}{
		{
			name:        "resolve specific version",
			rulesetName: "dca",
			version:     "v1.0.1",
			expectError: false,
		},
		{
			name:        "resolve latest symlink",
			rulesetName: "dca",
			version:     "latest",
			expectError: false,
		},
		{
			name:          "ruleset does not exist",
			rulesetName:   "nonexistent",
			version:       "v1.0.0",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "version does not exist",
			rulesetName:   "dca",
			version:       "v99.99.99",
			expectError:   true,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := usecase.resolveVersion(s, tt.rulesetName, tt.version)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
					return
				}
				if result == "" {
					t.Error("Expected non-empty result path")
				}
				// Verify the path exists
				if _, err := os.Stat(result); err != nil {
					t.Errorf("Resolved path does not exist: %s", result)
				}
			}
		})
	}
}

func TestRulesetDownloadUseCase_readMetadata(t *testing.T) {
	// Initialize logger
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	projectRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get project root: %v", err)
	}
	testStoragePath := filepath.Join(projectRoot, "test-support", "rulesets")

	if _, err := os.Stat(testStoragePath); os.IsNotExist(err) {
		t.Skipf("Test data not found at %s, skipping tests", testStoragePath)
	}

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = testStoragePath

	usecase := NewRulesetDownload(config)
	s := zlog.S

	tests := []struct {
		name          string
		versionPath   string
		expectError   bool
		errorContains string
		validateMeta  func(t *testing.T, meta RulesetMetadata)
	}{
		{
			name:        "read valid metadata",
			versionPath: filepath.Join(testStoragePath, "dca", "v1.0.1"),
			expectError: false,
			validateMeta: func(t *testing.T, meta RulesetMetadata) {
				if meta.Name != "dca" {
					t.Errorf("Expected name 'dca', got '%s'", meta.Name)
				}
				if meta.Version != "v1.0.1" {
					t.Errorf("Expected version 'v1.0.1', got '%s'", meta.Version)
				}
				if meta.ChecksumSHA256 == "" {
					t.Error("Expected non-empty checksum")
				}
			},
		},
		{
			name:          "metadata file does not exist",
			versionPath:   filepath.Join(testStoragePath, "nonexistent"),
			expectError:   true,
			errorContains: "failed to read metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := usecase.readMetadata(s, tt.versionPath)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
					return
				}
				if tt.validateMeta != nil {
					tt.validateMeta(t, result)
				}
			}
		})
	}
}

func TestRulesetDownloadUseCase_readTarball(t *testing.T) {
	// Initialize logger
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}
	defer zlog.SyncZap()

	projectRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get project root: %v", err)
	}
	testStoragePath := filepath.Join(projectRoot, "test-support", "rulesets")

	if _, err := os.Stat(testStoragePath); os.IsNotExist(err) {
		t.Skipf("Test data not found at %s, skipping tests", testStoragePath)
	}

	config := &myconfig.ServerConfig{}
	config.Rulesets.StoragePath = testStoragePath

	usecase := NewRulesetDownload(config)
	s := zlog.S

	tests := []struct {
		name           string
		versionPath    string
		rulesetName    string
		rulesetVersion string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "read valid tarball",
			versionPath:    filepath.Join(testStoragePath, "dca", "v1.0.1"),
			rulesetName:    "dca",
			rulesetVersion: "v1.0.1",
			expectError:    false,
		},
		{
			name:           "tarball does not exist",
			versionPath:    filepath.Join(testStoragePath, "dca", "v1.0.1"),
			rulesetName:    "dca",
			rulesetVersion: "v99.99.99",
			expectError:    true,
			errorContains:  "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := usecase.readTarball(s, tt.versionPath, tt.rulesetName, tt.rulesetVersion)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
					return
				}
				if len(result) == 0 {
					t.Error("Expected non-empty tarball data")
				}
			}
		})
	}
}

func TestRulesetMetadata_JSON(t *testing.T) {
	// Test JSON marshaling/unmarshaling
	original := RulesetMetadata{
		Name:           "test-ruleset",
		Version:        "v1.0.0",
		Description:    "Test description",
		CreatedAt:      "2025-01-01T00:00:00Z",
		ChecksumSHA256: "abc123",
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	// Unmarshal back
	var decoded RulesetMetadata
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal metadata: %v", err)
	}

	// Verify fields
	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: expected '%s', got '%s'", original.Name, decoded.Name)
	}
	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: expected '%s', got '%s'", original.Version, decoded.Version)
	}
	if decoded.Description != original.Description {
		t.Errorf("Description mismatch: expected '%s', got '%s'", original.Description, decoded.Description)
	}
	if decoded.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt mismatch: expected '%s', got '%s'", original.CreatedAt, decoded.CreatedAt)
	}
	if decoded.ChecksumSHA256 != original.ChecksumSHA256 {
		t.Errorf("ChecksumSHA256 mismatch: expected '%s', got '%s'", original.ChecksumSHA256, decoded.ChecksumSHA256)
	}
}
