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

package dtos

type Status string

const (
	ComponentNotFound    Status = "COMPONENT_NOT_FOUND"
	ComponentMalformed   Status = "COMPONENT_MALFORMED"
	ComponentWithoutInfo Status = "COMPONENT_WITHOUT_INFO"
	StatusSuccess        Status = "SUCCESS"
)

type CryptoOutput struct {
	Cryptography []CryptoOutputItem `json:"purls"`
}

type CryptoOutputItem struct {
	Purl        string            `json:"purl"`
	Version     string            `json:"version"`
	Requirement string            `json:"requirement"`
	Status      Status            `json:"status"`
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
	Purl        string            `json:"purl"`
	Requirement string            `json:"requirement"`
	Versions    []string          `json:"versions"`
	Algorithms  []CryptoUsageItem `json:"algorithms"`
	Status      Status            `json:"status"`
}

type VersionsInRangeOutput struct {
	Versions []VersionsInRangeUsingCryptoItem `json:"purls"`
}

type VersionsInRangeUsingCryptoItem struct {
	Purl            string   `json:"purl"`
	VersionsWith    []string `json:"versions_with"`
	VersionsWithout []string `json:"versions_without"`
}
