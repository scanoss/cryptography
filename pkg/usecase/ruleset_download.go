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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
)

// RulesetMetadata represents the manifest.json structure.
type RulesetMetadata struct {
	ChecksumSHA256 string `json:"checksum_sha256"`
	CreatedAt      string `json:"created_at"`
	Description    string `json:"description,omitempty"`
	Name           string `json:"name"`
	Version        string `json:"version"`
}

// RulesetDownloadOutput contains the tarball data and metadata.
type RulesetDownloadOutput struct {
	Metadata    RulesetMetadata
	TarballData []byte
}

// RulesetDownloadUseCase handles the business logic for downloading rulesets.
type RulesetDownloadUseCase struct {
	config *myconfig.ServerConfig
}

// NewRulesetDownload creates a new RulesetDownloadUseCase.
func NewRulesetDownload(config *myconfig.ServerConfig) *RulesetDownloadUseCase {
	return &RulesetDownloadUseCase{
		config: config,
	}
}

// verifyPathContainment ensures the resolved path is contained within the base directory.
// This prevents path traversal attacks where filepath.Join could resolve .. segments to escape.
func (r *RulesetDownloadUseCase) verifyPathContainment(resolvedPath, baseDir string) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}

	absResolved, err := filepath.Abs(resolvedPath)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	// Ensure the resolved path starts with the base directory followed by a separator
	// This prevents cases where "/base/dir" would match "/base/dir-malicious"
	if !strings.HasPrefix(absResolved, absBase+string(filepath.Separator)) && absResolved != absBase {
		return fmt.Errorf("path escapes base directory")
	}

	return nil
}

// resolveVersion resolves a version string (potentially "latest") to an actual version directory path
// It handles symlink resolution for "latest" version.
func (r *RulesetDownloadUseCase) resolveVersion(s *zap.SugaredLogger, rulesetName, version string) (string, error) {
	basePath := filepath.Join(r.config.Rulesets.StoragePath, rulesetName)

	// Verify the resolved path is contained within the storage directory
	if err := r.verifyPathContainment(basePath, r.config.Rulesets.StoragePath); err != nil {
		return "", fmt.Errorf("invalid ruleset name: %w", err)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		s.Warnf("Ruleset directory does not exist: %s", basePath)
		return "", fmt.Errorf("ruleset '%s' not found", rulesetName)
	}

	versionPath := filepath.Join(basePath, version)

	// If version is "latest", it should be a symlink
	if version == "latest" {
		targetPath, err := os.Readlink(versionPath)
		if err != nil {
			s.Warnf("Failed to read 'latest' symlink for ruleset %s: %v", rulesetName, err)
			return "", fmt.Errorf("failed to resolve 'latest' version for ruleset '%s'", rulesetName)
		}

		// If targetPath is relative, resolve it relative to basePath
		if !filepath.IsAbs(targetPath) {
			versionPath = filepath.Join(basePath, targetPath)
		} else {
			versionPath = targetPath
		}
		s.Debugf("Resolved 'latest' symlink for %s to: %s", rulesetName, versionPath)

		// Verify the resolved symlink target is contained within the storage directory
		if err := r.verifyPathContainment(versionPath, r.config.Rulesets.StoragePath); err != nil {
			s.Warnf("Symlink target escapes storage directory: %s", versionPath)
			return "", fmt.Errorf("invalid symlink target: %w", err)
		}
	}

	if _, err := os.Stat(versionPath); os.IsNotExist(err) {
		s.Warnf("Version directory does not exist: %s", versionPath)
		return "", fmt.Errorf("version '%s' not found for ruleset '%s'", version, rulesetName)
	}

	return versionPath, nil
}

// readMetadata reads and parses the manifest.json file from the version directory.
func (r *RulesetDownloadUseCase) readMetadata(s *zap.SugaredLogger, versionPath string) (RulesetMetadata, error) {
	metadataPath := filepath.Join(versionPath, "manifest.json")

	s.Debugf("Reading metadata from: %s", metadataPath)

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		s.Warnf("Failed to read metadata file %s: %v", metadataPath, err)
		return RulesetMetadata{}, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata RulesetMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		s.Warnf("Failed to parse metadata JSON from %s: %v", metadataPath, err)
		return RulesetMetadata{}, fmt.Errorf("failed to parse metadata: %w", err)
	}

	s.Debugf("Successfully parsed metadata: name=%s, version=%s, checksum=%s",
		metadata.Name, metadata.Version, metadata.ChecksumSHA256)

	return metadata, nil
}

// readTarball reads the tarball file into memory.
func (r *RulesetDownloadUseCase) readTarball(s *zap.SugaredLogger, versionPath, rulesetName, rulesetVersion string) ([]byte, error) {
	fileName := fmt.Sprintf("%s-%s.tar.gz", rulesetName, rulesetVersion)
	tarballPath := filepath.Join(versionPath, fileName)

	s.Debugf("Reading tarball from: %s", tarballPath)

	fileInfo, err := os.Stat(tarballPath)
	if err != nil {
		s.Warnf("Failed to stat tarball file %s: %v", tarballPath, err)
		return nil, fmt.Errorf("tarball file not found: %w", err)
	}

	s.Debugf("Tarball file size: %d bytes", fileInfo.Size())

	data, err := os.ReadFile(tarballPath)
	if err != nil {
		s.Warnf("Failed to read tarball file %s: %v", tarballPath, err)
		return nil, fmt.Errorf("failed to read tarball: %w", err)
	}

	s.Debugf("Successfully read %d bytes from tarball", len(data))

	return data, nil
}

// verifyTarballChecksum validates the SHA256 checksum of the tarball data against the expected checksum.
// It returns an error if the checksum is empty, mismatched, or if there's any validation failure.
func (r *RulesetDownloadUseCase) verifyTarballChecksum(s *zap.SugaredLogger, tarballData []byte, expectedChecksum string) error {
	// Check if expected checksum is empty
	if strings.TrimSpace(expectedChecksum) == "" {
		return fmt.Errorf("expected checksum is empty, cannot validate tarball integrity")
	}

	// Compute SHA256 of the tarball data
	hash := sha256.Sum256(tarballData)
	actualChecksum := hex.EncodeToString(hash[:])

	s.Debugf("Tarball checksum validation: expected=%s, actual=%s", expectedChecksum, actualChecksum)

	// Compare checksums
	if actualChecksum != strings.ToLower(expectedChecksum) {
		s.Warnf("Checksum mismatch! Expected: %s, Actual: %s", expectedChecksum, actualChecksum)
		return fmt.Errorf("tarball integrity check failed")
	}

	s.Debugf("Tarball checksum validation passed")
	return nil
}

// DownloadRuleset orchestrates the entire ruleset download process.
func (r *RulesetDownloadUseCase) DownloadRuleset(ctx context.Context, s *zap.SugaredLogger, rulesetName, version string) (RulesetDownloadOutput, error) {
	if err := ctx.Err(); err != nil {
		return RulesetDownloadOutput{}, fmt.Errorf("request cancelled: %w", err)
	}

	resolvedVersionPath, err := r.resolveVersion(s, rulesetName, version)
	if err != nil {
		return RulesetDownloadOutput{}, err
	}

	metadata, err := r.readMetadata(s, resolvedVersionPath)
	if err != nil {
		return RulesetDownloadOutput{}, err
	}

	tarballData, err := r.readTarball(s, resolvedVersionPath, metadata.Name, metadata.Version)
	if err != nil {
		return RulesetDownloadOutput{}, err
	}

	if err := r.verifyTarballChecksum(s, tarballData, metadata.ChecksumSHA256); err != nil {
		return RulesetDownloadOutput{}, fmt.Errorf("tarball integrity check failed: %w", err)
	}

	return RulesetDownloadOutput{
		TarballData: tarballData,
		Metadata:    metadata,
	}, nil
}
