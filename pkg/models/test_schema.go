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

// The serving schema, used to build the database the tests run against.
//
// The fixtures under tests/ used to carry their own CREATE TABLE statements, each
// describing the table as that fixture's author imagined it. Keeping the schema
// here instead means every test is built from one description, and a query naming
// a column the real database does not have fails in CI rather than in production.
//
// This is a transcription of the serving schema, taken from the production DuckDB
// file with `SELECT sql FROM duckdb_tables()`. The types are the SQLite
// equivalents, since the tests run on SQLite: DuckDB UUID becomes TEXT, which the
// queries already tolerate because they cast it.
//
// Keep this in step with the real database. It is a transcription, so it can drift;
// when a query fails in production but passes here, suspect this file first.

package models

// testSchemaDDL is the schema every DB-backed test is built from.
const testSchemaDDL = `
-- Component identity. purl is the versionless purl string; purl_id and
-- source_purl_id are UUID in DuckDB, TEXT here.
CREATE TABLE component (purl TEXT, vendor TEXT, component TEXT, source_purl_id TEXT, purl_id TEXT);
CREATE INDEX idx_component_purl ON component (purl);
CREATE INDEX idx_component_purl_id ON component (purl_id);

CREATE TABLE component_version (purl_id TEXT, version TEXT, version_name TEXT, version_semver TEXT);
CREATE INDEX idx_component_version_purl_id ON component_version (purl_id);

-- Cryptography, keyed by (purl_id, version). The mining schema keyed these by
-- url_hash, the hash of a package archive, reached through all_urls.
CREATE TABLE component_version_crypto (purl_id TEXT, version TEXT, algorithm_id TEXT);
CREATE INDEX idx_cvc_purl_id ON component_version_crypto (purl_id, version);

-- The algorithm catalogue. id is the short name the API emits ("aes"), and is what
-- component_version_crypto.algorithm_id holds; name is the long description, which
-- the API does not emit. strength is stored here, so it is read rather than derived.
--
-- This table was (id INTEGER, name TEXT) with the short name in name. When the
-- export moved to mining's current crypto model the short name moved to id and name
-- became the description, so a query selecting name started returning "Advanced
-- Encryption Standard" where the API contract wants "aes".
CREATE TABLE crypto_algorithm (id TEXT, name TEXT, category TEXT, strength TEXT, spdx_id TEXT);
CREATE INDEX idx_crypto_algorithm_id ON crypto_algorithm (id);

CREATE TABLE component_version_crypto_library (library_id TEXT, purl_id TEXT, version TEXT);
CREATE INDEX idx_cvcl_purl_id ON component_version_crypto_library (purl_id, version);

CREATE TABLE crypto_library (id TEXT, name TEXT, url TEXT, purl TEXT, category TEXT, description TEXT);
CREATE INDEX idx_crypto_library_id ON crypto_library (id);
`
