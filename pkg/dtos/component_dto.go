// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2025 SCANOSS.COM
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

// ComponentDTO represents a software component with its Package URL and version information.
type ComponentDTO struct {
	Purl        string `json:"purl"`                  // Package URL identifier
	Requirement string `json:"requirement,omitempty"` // Version requirement specification
	Version     string `json:"version,omitempty"`     // Specific version of the component
	Status      Status `json:"status"`                // Processing status of the component
}
