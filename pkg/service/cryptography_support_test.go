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

package service

import (
	"fmt"
	"testing"

	common "github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/cryptography/pkg/dtos"
)

func TestOutputConvert(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	var outputDto = dtos.CryptoOutput{}
	output, err := convertCryptoOutput(zlog.S, outputDto)
	if err != nil {
		t.Errorf("TestOutputConvert failed: %v", err)
	}
	fmt.Printf("Output: %v\n", output)
}

func TestInputConvert(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	var cryptoIn = &common.PurlRequest{}
	input, err := convertCryptoInput(zlog.S, cryptoIn)
	if err != nil {
		t.Errorf("TestInputConvert failed: %v", err)
	}
	fmt.Printf("Input: %v\n", input)
}
