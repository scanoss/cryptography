// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2024 SCANOSS.COM
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
	"bytes"
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"path/filepath"
	myconfig "scanoss.com/cryptography/pkg/config"
	"strings"
	"time"
)

type CryptoItem struct {
	Algorithm string
	Strength  string
}

type LdbModel struct {
	ctx    context.Context
	s      *zap.SugaredLogger
	config *myconfig.ServerConfig
}

// NewLdbModel creates a new instance of LDB Model
func NewLdbModel(ctx context.Context, s *zap.SugaredLogger, config *myconfig.ServerConfig) *LdbModel {
	return &LdbModel{ctx: ctx, s: s, config: config}
}

// PingLDB checks if the LBD and minimum tables.
func (m LdbModel) PingLDB(tables []string) error {
	ldbPath := filepath.Join(m.config.LDB.LdbPath, m.config.LDB.LdbName)
	entries, err := os.ReadDir(ldbPath)
	if err != nil {
		m.s.Errorf("Problem reading LDB path %s: %v", ldbPath, err)
		return errors.New("Problem opening LDB path " + ldbPath)
	}
	// Get existing table names
	var existingTables = make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			existingTables[e.Name()] = true
		}
	}
	// Check if the requested tables exist or not
	for _, table := range tables {
		if !existingTables[table] {
			return fmt.Errorf("LDB table %s does not exist", table)
		}
	}
	m.s.Debugf("LDB %s and tables %v exists", ldbPath, tables)
	return nil
}

// runLdbCommandFile runs the specified query file against the LDB
func (m LdbModel) runLdbCommandFile(queryFile string) ([]byte, error) {
	var args []string
	args = append(args, "-f", queryFile)
	m.s.Debugf("Executing %v %v", m.config.LDB.Binary, strings.Join(args, " "))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.config.LDB.Timeout)*time.Second) // put a timeout on the scan execution
	defer cancel()
	output, err := exec.CommandContext(ctx, m.config.LDB.Binary, args...).Output()
	if err != nil {
		m.s.Errorf("LDB command (%v %v) failed: %v", m.config.LDB.Binary, args, err)
		m.s.Errorf("Command output: %s", bytes.TrimSpace(output))
		return nil, fmt.Errorf("failed to run ldb: %v", err)
	}
	if m.config.LDB.Debug {
		m.s.Debugf("LDB command output: %s", bytes.TrimSpace(output))
	}
	return output, nil
}

// QueryBulkPivotLDB queries the LDB Pivot table checking for the requested keys.
// It will return a map of the related MD5 files related to the URL.
func (m LdbModel) QueryBulkPivotLDB(keys []string) (map[string][]string, error) {
	tempFile, err := os.CreateTemp("", "*pivot.txt")
	if err != nil {
		m.s.Errorf("Failed to create temporary SBOM file: %v", err)
		return nil, err
	}
	defer removeFile(tempFile, m.s)
	for _, key := range keys {
		if key != "" {
			query := fmt.Sprintf("select from %s/%s key %s csv hex 32\n", m.config.LDB.LdbName, m.config.LDB.PivotTable, key)
			_, err := tempFile.WriteString(query)
			if err != nil {
				m.s.Errorf("Problem writing to %s: %v", tempFile.Name(), err)
				closeFile(tempFile, m.s)
				return nil, fmt.Errorf("failed to write to temporary pivot LDB file")
			}
		}
	}
	closeFile(tempFile, m.s)
	output, err := m.runLdbCommandFile(tempFile.Name())
	if err != nil {
		return nil, err
	}
	ret := make(map[string][]string)
	if len(output) > 0 {
		// split results line by line. each row contains 3 values: <UrlMD5>,<FileMD5>,unknown
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if len(line) > 0 {
				fields := strings.Split(line, ",")
				if len(fields) >= 2 {
					ret[fields[0]] = append(ret[fields[0]], fields[1])
				}
			}
		}
	}
	return ret, nil
}

// QueryBulkCryptoLDB runs a bulk query of the crypto table for MD5 files
func (m LdbModel) QueryBulkCryptoLDB(items map[string][]string) (map[string][]CryptoItem, error) {
	tempFile, err := os.CreateTemp("", "*crypto.txt")
	if err != nil {
		m.s.Errorf("Failed to create temporary SBOM file: %v", err)
		return nil, err
	}
	defer removeFile(tempFile, m.s)
	// Produce a query for the unique list of MD5 files to check for crypto
	added := make(map[string]bool)
	for _, fileHashes := range items {
		for _, fileHash := range fileHashes {
			// Only add a query once
			if _, exist := added[fileHash]; !exist {
				query := fmt.Sprintf("select from %s/%s key %s csv hex 16\n", m.config.LDB.LdbName, m.config.LDB.CryptoTable, fileHash)
				_, err := tempFile.WriteString(query)
				if err != nil {
					m.s.Errorf("Problem writing to %s: %v", tempFile.Name(), err)
					closeFile(tempFile, m.s)
					return nil, fmt.Errorf("failed to write to temporary crypto LDB file")
				}
				added[fileHash] = true
			}
		}
	}
	closeFile(tempFile, m.s)
	output, err := m.runLdbCommandFile(tempFile.Name())
	if err != nil {
		return nil, err
	}
	algorithms := make(map[string][]CryptoItem)
	if len(output) > 0 {
		// Extract crypto algorithms for each entry
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if len(line) > 0 {
				fields := strings.Split(line, ",")
				if len(fields) == 3 {
					algorithm := CryptoItem{Algorithm: fields[1], Strength: fields[2]}
					algorithms[fields[0]] = append(algorithms[fields[0]], algorithm)
				} else {
					m.s.Warnf("Unexpected line in crypto reponse: %s", line)
				}
			}
		}
	}
	return algorithms, nil
}
