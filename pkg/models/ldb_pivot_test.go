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

package models

import (
	"testing"

	zlog "scanoss.com/cryptography/pkg/logger"
)

func TestQueryPivotLDB(t *testing.T) {
	//ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	LDBPivotTableName = "oss/pivot"
	LDBCryptoTableName = "quique/ncrypto"
	LDBBinPath = "/home/scanoss/Quique/cryptography/./ldb"

	_, err = PingLDB(LDBCryptoTableName)
	if err != nil {
		t.Fatalf(" '%s' LDB table not found", LDBCryptoTableName)
	}

	//URL hashes for engine 4.1.8,minr 2.4.0
	urlHashesForTesting := []string{"85fd290773dc4c859eabe63bc4b24e28", "d9c54ce52952bacf8b08dff6fdf7e577"}
	res, err := QueryBulkPivotLDB(urlHashesForTesting)
	if len(res["85fd290773dc4c859eabe63bc4b24e28"]) == 0 || len(res["d9c54ce52952bacf8b08dff6fdf7e577"]) == 0 {
		t.Fatalf("Pivot table can not retrieve results")
	}
}
