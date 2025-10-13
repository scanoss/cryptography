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

// Package models contains all the logic required to interact with the SCANOSS database.
// It provides data structures and database access layer for cryptography analysis and export control detection.
// The package encapsulates database queries and data transformation logic, serving as the data access layer
// for the cryptography service.
//
// Database Models and Tables:
//
// AllUrlsModel (all_urls.go):
// - Manages the 'all_urls' table which stores component package information
// - Provides queries to retrieve components by PURL (Package URL) specifications
// - Supports exact version matching, version range queries, and semantic versioning
// - Integrates with 'mines' and 'versions' tables for comprehensive package metadata
// - Key operations:
//   - GetUrlsByPurlList: Batch retrieval of components
//   - GetUrlsByPurlNameType: Query by package name and type
//   - GetUrlsByPurlNameTypeVersion: Query by specific version
//   - GetUrlsByPurlNameTypeInRange: Query versions within semantic version ranges
//   - PickClosestUrls: Version resolution and constraint matching
//
// CryptoUsageModel (crypto_usage.go):
// - Manages the 'component_crypto' table storing cryptographic algorithm usage
// - Tracks which cryptographic algorithms and their strength levels are used in components
// - Links URL hashes to specific cryptographic implementations
// - Key operations:
//   - GetCryptoUsageByURLHashes: Retrieves crypto algorithm usage for given component URLs
//
// ECUsageModel (library_usage.go):
// - Manages export control (EC) detection and library usage data
// - Works with 'component_crypto_library' and 'crypto_libraries' tables
// - Identifies libraries that may be subject to export control regulations
// - Provides detection metadata including IDs, names, descriptions, and categories
// - Key operations:
//   - GetLibraryUsageByURLHashes: Retrieves EC hints and library detections for components
//
// Supporting Structures:
//
// QuerySummary (query_summary.go):
// - Aggregates query execution results and error tracking
// - Categorizes failures by type: parse errors, missing info, not found, invalid semver
// - Used for debugging and reporting purposes across bulk operations
//
// Common utilities (common.go):
// - Database connection management (CloseDB, CloseConn)
// - Test data loading and SQL execution helpers
// - SQLite test setup for unit testing
//
// The models package follows a repository pattern, where each model struct encapsulates
// database access for a specific domain entity. All models accept a *sqlx.DB connection
// and provide methods that return structured data or errors.
package models
