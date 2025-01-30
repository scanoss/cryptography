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

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
)

func TestParseCryptoInput(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	var cryptoRequest = `{
				"purls": [
				  {
					"purl": "pkg:github/pineappleea/pineapple-src",
					"requirement":">=0"
					
				  }
				]
				}`
	requestDto, err := ParseCryptoInput(s, []byte(cryptoRequest))
	_ = requestDto
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	if requestDto.Purls[0].Purl != "pkg:github/pineappleea/pineapple-src" || requestDto.Purls[0].Requirement != ">=0" {
		t.Fatalf("Corrupted unmarshalled data")
	}
	cryptoRequest = ` `
	requestDto, err = ParseCryptoInput(s, []byte(cryptoRequest))
	if err == nil {
		t.Fatalf("Expected to get an error on empty json")
	}
	cryptoRequest = ``
	requestDto, err = ParseCryptoInput(s, []byte(cryptoRequest))
	if err == nil {
		t.Fatalf("Expected to get an error on empty json")
	}
}
