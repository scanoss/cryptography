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
	"go.uber.org/zap"
)

type CryptoInput struct {
	Purls []CryptoInputItem `json:"purls"`
}

type CryptoInputItem struct {
	Purl        string `json:"purl"`
	Requirement string `json:"requirement,omitempty"`
}

// ParseCryptoInput converts the input byte array to a CryptoInput structure
func ParseCryptoInput(s *zap.SugaredLogger, input []byte) (CryptoInput, error) {
	fmt.Println(string(input))
	if input == nil || len(input) == 0 {
		return CryptoInput{}, errors.New("no purl info data supplied to parse")
	}
	var data CryptoInput
	err := json.Unmarshal(input, &data)
	if err != nil {
		s.Errorf("Parse failure: %v", err)
		return CryptoInput{}, errors.New(fmt.Sprintf("failed to parse cryptography input data: %v", err))
	}
	s.Debugf("Parsed data2: %v", data)
	return data, nil
}
