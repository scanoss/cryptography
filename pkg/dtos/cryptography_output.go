// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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

import (
	"encoding/json"
	"errors"
	"fmt"

	zlog "scanoss.com/cryptography/pkg/logger"
)

type CryptoOutput struct {
	Cryptography []CryptoOutputItem `json:"purls"`
}

type CryptoOutputItem struct {
	Purl       string            `json:"purl"`
	Version    string            `json:"version"`
	Algorithms []CryptoUsageItem `json:"algorithms"`
}

type CryptoUsageItem struct {
	Algorithm string `json:"algorithm"`
	Strength  string `json:"strength"`
}

// ExportCryptoOutput converts the CryptoOutput structure to a byte array
func ExportCryptoOutput(output CryptoOutput) ([]byte, error) {
	data, err := json.Marshal(output)
	if err != nil {
		zlog.S.Errorf("Parse failure: %v", err)
		return nil, errors.New("failed to produce JSON from crypto output data")
	}
	return data, nil
}

// ParseCryptoOutput converts the input byte array to a CryptoOutput structure
func ParseCryptoOutput(input []byte) (CryptoOutput, error) {
	if input == nil || len(input) == 0 {
		return CryptoOutput{}, errors.New("no output Cryptography data supplied to parse")
	}
	var data CryptoOutput
	err := json.Unmarshal(input, &data)
	if err != nil {
		zlog.S.Errorf("Parse failure: %v", err)
		return CryptoOutput{}, errors.New(fmt.Sprintf("failed to parse Cryptography output data: %v", err))
	}
	zlog.S.Debugf("Parsed data2: %v", data)
	return data, nil
}
