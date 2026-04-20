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

// Package testutils provides shared helpers used across the cryptography
// service's test suites (filesystem fixtures, environment setup, etc.).
package testutils

import (
	"os"
	"testing"
)

// SetupTestRulesetsDir creates a temporary rulesets directory for testing
// and sets the RULESETS_STORAGE_PATH environment variable.
// Returns a cleanup function that should be deferred.
//
// Usage:
//
//	func TestMyFunction(t *testing.T) {
//	    defer testutils.SetupTestRulesetsDir(t)()
//	    // ... test code
//	}
func SetupTestRulesetsDir(t *testing.T) func() {
	tmpDir, err := os.MkdirTemp("", "rulesets-test-*")
	if err != nil {
		t.Fatalf("failed to create temp rulesets directory: %v", err)
	}

	err = os.Setenv("RULESETS_STORAGE_PATH", tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to set RULESETS_STORAGE_PATH: %v", err)
	}

	return func() {
		os.Unsetenv("RULESETS_STORAGE_PATH")
		os.RemoveAll(tmpDir)
	}
}
