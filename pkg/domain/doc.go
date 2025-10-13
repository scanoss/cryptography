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

// Package domain contains the core domain models for the cryptography service.
// It provides data structures to represent cryptographic algorithm usage and export control information.
//
// Current domain models include:
// - ComponentStatus: Status information for component queries with status codes
// - CryptoOutput: Cryptographic algorithm usage information for specific component versions
// - CryptoInRangeOutput: Cryptographic algorithm usage for components within version ranges
// - VersionsInRangeOutput: Version lists categorized by cryptography usage
// - ECOutput: Export control hints and detections for components within version ranges
// - HintsOutput: Export control hints for specific component versions
package domain
