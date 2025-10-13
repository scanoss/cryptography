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

// Package usecase implements the business logic for cryptography analysis and export control detection.
// It orchestrates interactions between the data models layer and domain layer to provide
// high-level operations for analyzing cryptographic algorithm usage in software components.
//
// The package contains the following use cases:
//
// Component Validation:
// - parseAndValidateComponent: Validates and parses component DTOs, ensuring PURLs and version
//   requirements are correctly formatted and semantically valid according to Package URL specifications.
//
// Cryptographic Analysis:
// - CryptoUseCase: Retrieves cryptographic algorithm usage for specific component versions.
//   Given a list of components with specific versions or requirements, it identifies which
//   cryptographic algorithms are used in those versions.
//
// - CryptoMajorUseCase: Analyzes cryptographic algorithm usage across version ranges.
//   Given components with version range requirements (e.g., >=1.0.0, <2.0.0), it identifies
//   all versions within the range and the cryptographic algorithms used across those versions.
//
// - VersionsUsingCrypto: Categorizes versions within a range based on cryptography usage.
//   Returns two lists: versions that use cryptography and versions that don't, useful for
//   understanding cryptographic adoption across component versions.
//
// Export Control Detection:
// - ECDetectionUseCase: Detects export control hints and library usage patterns for components.
//   Provides two main operations:
//     * GetDetections: Finds export control hints for specific component versions
//     * GetDetectionsInRange: Finds export control hints for components within version ranges
//
// All use cases follow a consistent pattern:
// 1. Validate input components (PURL format, version requirements)
// 2. Query the database for relevant component versions and their associated data
// 3. Process and aggregate results
// 4. Return domain objects with appropriate status codes and messages
//
// Status codes used across use cases:
// - SUCCESS: Operation completed successfully with results
// - COMPONENT_NOT_FOUND: Component does not exist in the database
// - COMPONENT_WITHOUT_INFO: Component exists but has no cryptographic/EC information
// - INVALID_PURL: The provided PURL string is malformed or invalid
// - INVALID_SEMVER: The version requirement is invalid or malformed
package usecase