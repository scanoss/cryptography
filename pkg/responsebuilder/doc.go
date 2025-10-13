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

// Package responsebuilder provides utilities for building and converting internal
// data structures into protocol buffer response formats for the cryptography service.
//
// This package serves as the transformation layer between internal DTOs (Data Transfer Objects)
// and gRPC protocol buffer messages. It handles the conversion of cryptography-related data
// including algorithms, encryption hints, and version information from internal representations
// to API response formats.
//
// # Main Responsibilities
//
// The package provides builders for five main categories of responses:
//
//   - Algorithm Responses: Convert cryptographic algorithm data for specific component versions
//   - Algorithms In Range Responses: Convert algorithm data for version ranges
//   - Encryption Hints Responses: Convert encryption hint detections for specific versions
//   - Hints In Range Responses: Convert hint data for version ranges
//   - Versions In Range Responses: Convert version availability information
//
// Each category includes multiple response formats to support different API endpoints:
//   - Single response format (e.g., AlgorithmResponse)
//   - Component response format (e.g., ComponentAlgorithmsResponse)
//   - Components (plural) response format (e.g., ComponentsAlgorithmsResponse)
//
// # Response Building Process
//
// All builder functions follow a consistent pattern:
//
//  1. Marshal internal DTO to JSON
//  2. Unmarshal JSON into protobuf response structure
//  3. Enhance response with status information using httpresponsehelper
//  4. Return the complete response with error handling
//
// # Error Handling
//
// All builder functions return errors in the following scenarios:
//
//   - Marshalling failures when converting DTOs to JSON
//   - Unmarshalling failures when converting JSON to protobuf messages
//   - Missing or empty data in required fields (e.g., nil cryptography data)
//
// Error messages are logged using the provided zap.SugaredLogger and returned
// as user-friendly error descriptions.
package responsebuilder
