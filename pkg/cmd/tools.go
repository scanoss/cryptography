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

package cmd

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type DetectionsDefinition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Keywords    []string `json:"keywords"`
	URL         string   `json:"url,omitempty"`
	Category    string   `json:"category"`
	Purl        string   `json:"purl,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func normalize(str string) string {
	str = strings.ReplaceAll(str, "'", "")
	str = strings.ReplaceAll(str, "\"", "\\\"")
	return str
}

// RunServer runs the gRPC Cryptography Server.
func SupportTools() error {
	var defJSONPath string
	var createLibrariesTable string

	flag.StringVar(&defJSONPath, "json-definition", "", "Defines a json file path")
	flag.StringVar(&createLibrariesTable, "create-table", "", "Defines a table to be created")
	flag.Parse()
	defs := []DetectionsDefinition{}

	if createLibrariesTable != "" {
		data, errFile := os.ReadFile(defJSONPath)
		if errFile != nil {
			fmt.Printf("%+v", errFile)
		}
		err := json.Unmarshal(data, &defs)
		if err != nil {
			log.Fatal(err)
		}

		sqlContent := `CREATE TABLE if not exists "crypto_libraries" (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT NOT NULL,
		url TEXT NOT NULL,
		category TEXT NOT NULL,
		purl TEXT NOT NULL
	);`

		for _, def := range defs {
			line := fmt.Sprintf("\nINSERT INTO crypto_libraries VALUES('%s','%s','%s','%s','%s','%s');",
				normalize(def.ID), normalize(def.Name), normalize(def.Description), normalize(def.URL),
				normalize(def.Category), normalize(def.Purl))
			sqlContent += line
		}
		fmt.Print(sqlContent)
	}
	// zlog.S.Infof("Starting SCANOSS Cryptography Service: %v", strings.TrimSpace(version))
	return nil
}
