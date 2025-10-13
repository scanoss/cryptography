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

// Package usecase contains shared validation logic for component processing.
// This file provides validation functions used across multiple use cases to ensure
// consistent validation of component data, particularly Package URLs (PURLs) and
// version requirements.
package usecase

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"go.uber.org/zap"
	"scanoss.com/cryptography/pkg/domain"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/utils"
)

// parseAndValidateComponent validates and parses a component DTO, ensuring the PURL
// and version requirement are correctly formatted and semantically valid.
//
// This function performs comprehensive validation including:
//   - PURL syntax validation and parsing
//   - Wildcard requirement rejection ("*" and "v*" patterns)
//   - Empty requirement detection
//   - Semantic version requirement validation
//   - PURL name extraction and validation
//
// Validation Rules:
//   - The PURL must be parseable according to the PURL specification
//   - Requirements cannot be "*" or start with "v*" (wildcard patterns)
//   - Requirements cannot be empty strings
//   - Requirements must follow valid semantic versioning syntax
//   - The PURL must contain a valid package name component
//
// On validation failure, the function returns a ComponentStatus with:
//   - StatusCode indicating the type of error (InvalidPurl, InvalidSemver)
//   - A descriptive error message
//   - An error code for API response generation
//
// On success, returns:
//   - ComponentStatus with StatusCode set to Success
//   - Parsed PackageURL object
//   - Extracted PURL name
//
// Parameters:
//   - s: Structured logger for error reporting
//   - component: Component DTO containing purl and requirement fields to validate
//
// Returns:
//   - componentStatus: Validation result with status code, message, and error code
//   - packageURL: Parsed PackageURL object (nil on validation failure)
//   - purlName: Extracted package name from PURL (nil on validation failure)
func parseAndValidateComponent(s *zap.SugaredLogger, component dtos.ComponentDTO) (domain.ComponentStatus, *packageurl.PackageURL, *string) {
	purl, err := purlhelper.PurlFromString(component.Purl)
	if err != nil {
		s.Errorf("Failed to parse purl '%s': %s", component.Purl, err)
		return domain.ComponentStatus{StatusCode: domain.InvalidPurl, Message: fmt.Sprintf("Failed to parse purl %s", component.Purl)}, nil, nil
	}
	if component.Requirement == "*" || strings.HasPrefix(component.Requirement, "v*") {
		return domain.ComponentStatus{StatusCode: domain.InvalidSemver, Message: fmt.Sprintf("Invalid requirement: %s", purl)}, nil, nil
	}
	if component.Requirement == "" {
		return domain.ComponentStatus{StatusCode: domain.InvalidSemver, Message: fmt.Sprintf("Empty requirement %s", component.Requirement)}, nil, nil
	}
	if !utils.IsValidRequirement(component.Requirement) {
		return domain.ComponentStatus{StatusCode: domain.InvalidSemver, Message: fmt.Sprintf("Invalid requirement: %s", component.Requirement)}, nil, nil
	}
	pName, err := purlhelper.PurlNameFromString(component.Purl) // Make sure we just have the bare minimum for a Purl Name
	if err != nil {
		s.Errorf("Failed to parse purl '%s': %s", component.Purl, err)
		return domain.ComponentStatus{StatusCode: domain.InvalidPurl, Message: fmt.Sprintf("Failed to parse purl %s", purl)}, nil, nil
	}
	return domain.ComponentStatus{StatusCode: domain.Success}, &purl, &pName
}
