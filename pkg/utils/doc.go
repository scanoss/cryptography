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

// Package utils provides utility functions and data structures for common operations
// across the cryptography service. It contains helper functions for validation and
// data transformation that are used throughout the application.
//
// Data Structures (purl_req.go):
//
// PurlReq:
// - Simple struct for holding PURL (Package URL) and version pairs
// - Used for batch queries and component identification
// - Fields:
//   - Purl: Package URL name (e.g., "pkg:npm/lodash")
//   - Version: Specific version string (e.g., "4.17.21")
//
// This package is designed to be lightweight and focused on common utilities
// that don't fit into the domain, models, or usecase packages. All functions
// should be stateless and reusable across different contexts.
package utils
