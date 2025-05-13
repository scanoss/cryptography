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

type ECOutput struct {
	Hints []ECOutputItem `json:"purls"`
}

type ECOutputItem struct {
	Purl       string           `json:"purl"`
	Versions   []string         `json:"versions"`
	Detections []ECDetectedItem `json:"hints"`
}

type ECDetectedItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"URL,omitempty"`
	Categoty    string `json:"category"`
	Purl        string `json:"purl,omitempty"`
}

type HintsOutput struct {
	Hints []HintsOutputItem `json:"purls"`
}

type HintsOutputItem struct {
	Purl       string           `json:"purl"`
	Version    string           `json:"version"`
	Detections []ECDetectedItem `json:"hints"`
}
