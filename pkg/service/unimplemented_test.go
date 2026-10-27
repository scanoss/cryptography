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

package service

import (
	"reflect"
	"testing"
)

// The server must embed papi's generated Unimplemented struct, not the
// CryptographyServer interface.
//
// Embedding the interface leaves a nil value, and any method the service does not
// implement dereferences it and panics, taking the whole process down. Every
// method is implemented today, so nothing reaches it - which is exactly why this
// is worth pinning: the first method papi adds would otherwise become a remotely
// reachable crash, silently. The generated struct answers those with an
// Unimplemented error instead.
//
// scanoss/components shipped that crash: GetComponentStatistics arrived in papi
// v0.42.0, was never implemented, and one unauthenticated request killed the server.
func TestServerEmbedsUnimplementedStruct(t *testing.T) {
	serverType := reflect.TypeOf(cryptographyServer{})
	field, ok := serverType.FieldByName("UnimplementedCryptographyServer")
	if !ok {
		t.Fatalf("cryptographyServer must embed pb.UnimplementedCryptographyServer; fields: %v", fieldNames(serverType))
	}
	if !field.Anonymous {
		t.Error("UnimplementedCryptographyServer must be embedded, not a named field")
	}
	if field.Type.Kind() != reflect.Struct {
		t.Errorf("embedded papi type is a %v; embedding the interface leaves a nil value that panics", field.Type.Kind())
	}
	if _, isInterface := serverType.FieldByName("CryptographyServer"); isInterface {
		t.Error("cryptographyServer still embeds the CryptographyServer interface, whose nil value panics")
	}
}

func fieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return names
}
