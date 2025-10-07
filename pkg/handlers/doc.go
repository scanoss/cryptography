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

// Package handlers provides gRPC request handlers for the cryptography service.
//
// This package serves as the entry point for all gRPC requests to the cryptography service.
// It contains handler implementations that process incoming requests, coordinate with use cases,
// build appropriate responses, and handle errors and status codes. The handlers act as the
// controller layer in the service architecture, bridging the gRPC API with the business logic.
//
// # Handler Types
//
// The package provides several specialized handlers, each responsible for a specific domain:
//
//   - CryptographyAlgorithmHandler: Handles requests for cryptographic algorithms associated
//     with specific component versions
//   - AlgorithmInRangeHandler: Handles requests for cryptographic algorithms within version ranges
//   - EncryptionHintsHandler: Handles requests for encryption hint detections for specific versions
//   - HintsRangeHandler: Handles requests for encryption hints within version ranges
//   - VersionsInRangeHandler: Handles requests for version availability information
//     (versions with and without cryptographic detections)
//
// Each handler supports three request patterns:
//   - Deprecated legacy format (PurlRequest)
//   - Multiple components format (ComponentsRequest)
//   - Single component format (ComponentRequest)
//
// # Request Processing Flow
//
// All handlers follow a consistent request processing pattern:
//
//  1. Extract logger from context using ctxzap
//  2. Validate incoming request (purls, components, requirements)
//  3. Convert request to internal DTO format
//  4. Execute business logic through use case layer
//  5. Convert output to protobuf response format using responsebuilder
//  6. Handle errors and set appropriate status codes
//  7. Return response to gRPC client
//
// # Request Validation
//
// The package provides generic validation functions using Go generics:
//
//   - rejectIfInvalidComponents: Validates ComponentsRequest (multiple components)
//   - rejectIfInvalid: Validates ComponentRequest (single component)
//
// These functions use the guard clause pattern and generic type parameters to
// support any response type, making validation reusable across all handlers.
//
// # Error Handling
//
// Handlers implement comprehensive error handling:
//
//   - Request validation errors return FAILED status with descriptive messages
//   - Use case errors are logged and returned with appropriate status codes
//   - Response building errors result in FAILED status responses
//   - HTTP status codes are set in gRPC trailers for gateway compatibility
//
// All errors are logged using structured logging (zap) before returning responses.
// # Request Conversion
//
// The package includes utility functions for converting between API and internal formats:
//
//   - ConvertPurlRequestToComponentDTO: Converts legacy PurlRequest to ComponentDTO (deprecated)
//   - convertComponentsRequestToComponentDTO: Converts ComponentsRequest to ComponentDTO slice
//   - validateComponentRequest: Validates single ComponentRequest
//   - buildComponentDTO: Constructs ComponentDTO from purl and requirement strings
//
// These functions handle version parsing from PURL strings (e.g., "pkg:npm/foo@1.0.0")
// and extract requirement specifications.
//
// # Telemetry
//
// The package supports OpenTelemetry metrics:
//
//   - Request duration histograms
//   - Configurable telemetry enablement
//   - Metrics recorded per operation type
//
// Telemetry is configured through the ServerConfig and can be disabled
// for testing or when metrics collection is not needed.
package handlers
