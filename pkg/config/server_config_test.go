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

package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/golobby/config/v3"
	"github.com/golobby/config/v3/pkg/feeder"
	"scanoss.com/cryptography/pkg/testutils"
)

func TestServerConfig(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	dbUser := "test-user"
	err := os.Setenv("DB_USER", dbUser)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	defer os.Unsetenv("DB_USER")

	cfg, err := NewServerConfig(nil)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config1: %+v\n", cfg)
}

func TestServerConfigDotEnv(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	err := os.Unsetenv("DB_USER")
	if err != nil {
		fmt.Printf("Warning: Problem runn Unsetenv: %v\n", err)
	}

	dbUser := "env-user"
	var feeders []config.Feeder
	feeders = append(feeders, feeder.DotEnv{Path: "tests/dot-env"})
	cfg, err := NewServerConfig(feeders)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config2: %+v\n", cfg)
}

func TestServerConfigJson(t *testing.T) {
	defer testutils.SetupTestRulesetsDir(t)()

	err := os.Unsetenv("DB_USER")
	if err != nil {
		fmt.Printf("Warning: Problem runn Unsetenv: %v\n", err)
	}

	dbUser := "json-user"
	var feeders []config.Feeder
	feeders = append(feeders, feeder.Json{Path: "tests/env.json"})
	cfg, err := NewServerConfig(feeders)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when creating new config instance", err)
	}
	if cfg.Database.User != dbUser {
		t.Errorf("DB user '%v' doesn't match expected: %v", cfg.Database.User, dbUser)
	}
	fmt.Printf("Server Config3: %+v\n", cfg)
}

func TestValidateRulesetsFolder(t *testing.T) {
	// Test with non-existent path
	t.Run("NonExistentPath", func(t *testing.T) {
		err := os.Setenv("RULESETS_STORAGE_PATH", "/path/that/does/not/exist")
		if err != nil {
			t.Fatalf("failed to set RULESETS_STORAGE_PATH: %s", err)
		}
		defer os.Unsetenv("RULESETS_STORAGE_PATH")

		_, err = NewServerConfig(nil)
		if err == nil {
			t.Fatal("expected error for non-existent rulesets path, got nil")
		}
		if !os.IsNotExist(err) && err.Error() != "rulesets storage path does not exist: /path/that/does/not/exist" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// Test with valid directory
	t.Run("ValidDirectory", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "rulesets-test-*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %s", err)
		}
		defer os.RemoveAll(tmpDir)

		err = os.Setenv("RULESETS_STORAGE_PATH", tmpDir)
		if err != nil {
			t.Fatalf("failed to set RULESETS_STORAGE_PATH: %s", err)
		}
		defer os.Unsetenv("RULESETS_STORAGE_PATH")

		cfg, err := NewServerConfig(nil)
		if err != nil {
			t.Fatalf("unexpected error for valid rulesets path: %s", err)
		}
		if cfg.Rulesets.StoragePath != tmpDir {
			t.Errorf("expected storage path %s, got %s", tmpDir, cfg.Rulesets.StoragePath)
		}
	})

	// Test with file instead of directory
	t.Run("FileInsteadOfDirectory", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "rulesets-file-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		err = os.Setenv("RULESETS_STORAGE_PATH", tmpFile.Name())
		if err != nil {
			t.Fatalf("failed to set RULESETS_STORAGE_PATH: %s", err)
		}
		defer os.Unsetenv("RULESETS_STORAGE_PATH")

		_, err = NewServerConfig(nil)
		if err == nil {
			t.Fatal("expected error for file instead of directory, got nil")
		}
		expectedMsg := fmt.Sprintf("rulesets storage path is not a directory: %s", tmpFile.Name())
		if err.Error() != expectedMsg {
			t.Errorf("expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})
}
