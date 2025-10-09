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

package domain

import (
	"github.com/package-url/packageurl-go"
	pb "github.com/scanoss/papi/api/cryptographyv2"
)

type ComponentStatus struct {
	Message    string
	Error      *pb.ErrorCode
	StatusCode StatusCode
}

type StatusCode string

const (
	ComponentNotFound    StatusCode = "COMPONENT_NOT_FOUND"
	InvalidPurl          StatusCode = "INVALID_PURL"
	ComponentWithoutInfo StatusCode = "COMPONENT_WITHOUT_INFO"
	Success              StatusCode = "SUCCESS"
	InvalidSemver        StatusCode = "INVALID_SEMVER"
)

type CryptoOutput struct {
	Cryptography []CryptoOutputItem `json:"purls"`
}

type CryptoOutputItem struct {
	Purl        string            `json:"purl"`
	Version     string            `json:"version"`
	Requirement string            `json:"requirement"`
	Status      ComponentStatus   `json:"status"`
	Algorithms  []CryptoUsageItem `json:"algorithms"`
}

type CryptoUsageItem struct {
	Algorithm string `json:"algorithm"`
	Strength  string `json:"strength"`
}

type CryptoInRangeOutput struct {
	Cryptography []CryptoInRangeOutputItem `json:"purls"`
}

type CryptoInRangeOutputItem struct {
	Purl        string                 `json:"purl"`
	Requirement string                 `json:"requirement"`
	Versions    []string               `json:"versions"`
	Algorithms  []CryptoUsageItem      `json:"algorithms"`
	Status      ComponentStatus        `json:"status"`
	PackageUrl  *packageurl.PackageURL `json:"package_url"`
	PurlName    *string                `json:"purl_name"`
}

type VersionsInRangeOutput struct {
	Versions []VersionsInRangeUsingCryptoItem `json:"purls"`
}

type VersionsInRangeUsingCryptoItem struct {
	Purl            string                 `json:"purl"`
	Status          ComponentStatus        `json:"status"`
	VersionsWith    []string               `json:"versions_with"`
	VersionsWithout []string               `json:"versions_without"`
	Requirement     string                 `json:"requirement"`
	PackageUrl      *packageurl.PackageURL `json:"package_url"`
	PurlName        *string                `json:"purl_name"`
}
