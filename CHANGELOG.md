# Changelog

## [Unreleased]

### Security
- **Hardened against an unimplemented method killing the server.** The service embedded the papi `CryptographyServer` *interface* rather than the generated `UnimplementedCryptographyServer`. The interface value is nil, so any method the service does not implement would dereference it and panic, taking the whole process down. Every method of the current papi interface is implemented, so nothing reaches it today - but the first method papi adds would, silently, as a remotely reachable crash. scanoss/components shipped exactly that: `GetComponentStatistics` arrived in papi v0.42.0, was never implemented, and one unauthenticated request killed the server

### Changed
- **The service now reads the serving knowledge base instead of the mining database.** The mining path is gone; there is no configuration that selects it. Endpoint routes and response shapes are unchanged
- **Cryptography is keyed by `(purl_id, version)` rather than by `url_hash`.** The mining lookup went purl → `all_urls` → `package_hash` → `component_crypto`; the hash was the identity of a package archive, and resolving it needed a join through `all_urls`, `mines` and `versions`. The serving schema records crypto against the component version directly, so the hash round-trip is gone
- Algorithms read `component_version_crypto ⋈ crypto_algorithm`; crypto-library hints read `component_version_crypto_library ⋈ crypto_library` (the renamed `crypto_libraries`)
- The IN-lists are bound parameters now. The mining queries built them by interpolating the values into the SQL string
- Component and version resolution no longer goes through `go-component-helper`, which resolves against `all_urls`, `mines` and `versions` - none of which exist in the serving schema. It is replaced by `pkg/resolver`, over `component` / `component_version`
- **The source-purl fallback now follows `component.source_purl_id`** instead of the mining `projects` table's source-mine columns. Its behaviour is unchanged: a component with no cryptographic information is retried against the repository it was built from, and the result carries `info_code: WARNING` naming the source purl
- The range endpoints filter the resolved component's own version set instead of a set of `all_urls` rows, so there is no purl type left to re-check: the resolution has already pinned one component
- An exact version now matches whether or not it carries a leading `v` (`5.4.7` finds `v5.4.7`), answering with the spelling the component publishes. The mining lookup did this through `SemverTogglePrefix`; the resolver reproduces it
- Binaries are built with `CGO_ENABLED=1`, and the runtime image moved to `debian:bookworm-slim` with `libstdc++6`. The DuckDB driver is a cgo binding, so a pure-Go build can no longer be produced

### Added
- **DuckDB support**, the intended production backend for the serving knowledge base. Set `DB_DRIVER=duckdb` and `DB_PATH` to the serving file, which is opened read-only
- `pkg/db`, opening the serving database for any of duckdb, sqlite or postgres
- `pkg/resolver`, the serving component resolution and the shared source-purl fallback
- `pkg/models/test_schema.go`, holding the serving schema the tests build their database from. The fixtures under `tests/` used to carry their own `CREATE TABLE` statements, each describing the table as that fixture's author imagined it

### Removed
- `pkg/models/all_urls.go`. Nothing resolves through package hashes any more

### Deployment
- **Breaking:** requires a serving knowledge base. Point `DB_PATH` at the `.duckdb` file and set `DB_DRIVER=duckdb`
- **Blocker: the serving export carries a narrower algorithm set.** `crypto_algorithm` holds only the 127 SPDX algorithms; the mining `component_crypto` records 224 distinct names, 125 of which serving shares. The 99 it does not fall into two kinds, and the distinction matters:
  - **No representation at all — 116,545,185 of 346,116,636 mining rows (33.7%).** `hmac` (13.1M rows), `gecc` (7.8M), `kdf2` (6.9M), `ecdsa` (6.5M), `kerberos` (6.4M), `pgp` (5.7M), `eddsa` (5.5M), `ecc` (5.0M), `ed25519` (4.6M), `mldsa` (3.0M), and the cipher modes `gcm` (6.0M), `cbc` (5.0M), `ctr`, `ecb`, `cfb`, `ofb`, `xts`. Serving has `ecdh` and `ecmqv` but no generic elliptic-curve entry, and `rc4-hmac` but no generic HMAC
  - **Represented, but collapsed into a coarser label — 59,603,548 rows (17.2%).** `sha1`/`sha2`/`sha3` (56.3M) all map onto the single `shax` entry, "SHA-x (SHA-1, SHA-256, etc.)", and `chacha20` (3.3M) onto `chacha`. The detection survives; the granularity does not. This mapping is inferred from the labels, not confirmed against the ETL
- Measured per component rather than per version string, `pkg:github/openssl/openssl` has 102 distinct algorithms in mining and 52 in serving, 48 shared: 50 with no serving representation and 4 collapsed into `shax`/`chacha`. **Do not merge until the export covers the missing algorithms**; this is an ETL gap, not a code one - the serving rows have no orphan algorithm ids
- `component_version_crypto` holds 171.5M rows against mining's 346.1M, consistent with the above
- **`strength` is derived, not stored.** The mining schema had a `strength` column; serving does not, so the value comes from the SPDX key sizes the way the current decoration service derives it. Of the algorithms present in both, 90 agree with mining and 35 do not, and a few read oddly because SPDX records a maximum below the common size (`des` becomes `168-56`, `cast` `320-128`, and `aes` `256` where mining said `128-256`). Matching the decoration service was the deliberate choice, so the two report the same thing
- Version strings can change for a given component: serving normalises them, so openssl's `OpenSSL_1_1_1a` is `1.0.1-s` there
- Verified against the production serving file (55.7 GiB): every endpoint, single and batch, including the source-purl fallback and the per-version range breakdown
- `make build_arm` now cross-compiles with cgo and needs an `aarch64` toolchain (set `CC`); the amd64 build is unaffected

## [0.12.0] - 2026-06-22
### Added
- `/health` liveness endpoint (GET) on the REST gateway

### Changed
- Upgraded `scanoss/go-grpc-helper` to `v0.16.0`

## [0.11.0] - 2026-06-02
### Added
- Integrated `go-component-helper` (`componenthelper.GetComponentsVersion`) as the single source of truth for resolving and validating version requirements, querying the same knowledge base (`all_urls`/`versions`/`mines`)
- Added a source-code purl fallback: when a cryptography or library lookup returns no info, the query is retried against the component's linked source purl; recovered results are flagged with a `WARNING` info_code and the message `Showing results from the source code purl (<source purl>)`
- Added `github.com/scanoss/go-component-helper` and `github.com/scanoss/go-models` dependencies

### Changed
- Centralized requirement resolution in `pkg/usecase/component_resolver.go`, replacing the divergent per-endpoint validation/resolution logic
- Range endpoints now return `VERSION_NOT_FOUND` (instead of `COMPONENT_NOT_FOUND`) when the component exists but no known version satisfies the requirement

### Removed
- Removed redundant local resolution helpers now provided by the component helper: `parseAndValidateComponent`, `utils.IsValidRequirement`, `processPurlVersion`, `models.PickClosestUrls`, `models.GetUrlsByPurlNameTypeInRange`

### Fixed
- Fixed `golangci-lint` issues (line length, unused parameter and always-nil return) and removed a stale lint exclusion


## [0.10.0] - 2026-04-20
### Changed
- Replaced `error_message`/`error_code` fields with `info_message`/`info_code` across response builders and domain structs (algorithms, algorithms in range, encryption hints, hints in range, versions in range)
- Removed `error_code_response_builder` in favor of info-based status handling in each response builder
- Updated dependencies to the latest versions
- Converted all `pkg/responsebuilder/` tests from CSV-driven cases to inline Go table tests with full-struct `assert.Equal` comparisons
- Removed `pkg/responsebuilder/testdata/` and its five CSV fixtures, along with the `mockServerTransportStream`, `TestCase`, `loadTestCases`, and `parseStatusCode` helpers that only existed to bridge the CSV encoding
- Updated `linter` to `v2.10.1`


## [0.9.0] - 2025-12-29
### Added
- Added gRPC DownloadRuleset and REST endpoint GET /v2/cryptography/rulesets/download
  - Supports downloading cryptography detection rulesets by name and version
  - Supports "latest" keyword for retrieving the most recent version
  - Returns tarball with appropriate HTTP headers (Content-Disposition, SCANOSS-Ruleset-Name, SCANOSS-Ruleset-Version, X-Checksum-SHA256)
  - Includes metadata validation and version resolution via symlinks

### Fixed
- Fixed OpenTelemetry metrics initialization by properly exporting SetupMetrics function 

## [0.8.1] - 2025-10-16
### Fixed
- Fixed OpenTelemetry metrics initialization by exporting SetupMetrics function and calling it on server startup

## [0.8.0] - 2025-10-13
### Added
- Added telemetry request time in cryptography handlers
- Added documentation

### Changed
- Enhanced response handling with detailed error messages and status codes for:
  - Encryption hints block responses
  - Hints in range block responses
  - Versions in range block responses
  - Algorithms in range responses
  - Algorithms block responses
- Refactored handlers for improved code quality:
  - Encryption hints handler
  - Hints in range handler
  - Version in range handler
  - Cryptography in range handler
- Implemented response builder package
- Removed duplicated validation code shared by ranges endpoints
- Removed protobuf error code from ComponentStatus domain struct

### Updated
- Upgraded scanoss/papi dependency to v0.25.1

## [0.7.1] - 2025-10-02
### Bug
- Fixed response status for batch operations

## [0.7.0] - 2025-09-30
### Added
- Added semver validation for ranges endpoints
- Added detailed response message about versions found in ranges endpoint responses

### Changed
- Enhanced response handling for ranges endpoints with query summaries

## [0.6.0] - 2025-09-12
### Added
- Added gRPC GetComponentAlgorithms and REST endpoint GET /v2/cryptography/algorithms/component
- Added gRPC GetComponentsAlgorithms and REST endpoint POST /v2/cryptography/algorithms/components
- Added gRPC GetComponentAlgorithmsInRange and REST endpoint GET /v2/cryptography/algorithms/range/component
- Added gRPC GetComponentsAlgorithmsInRange and REST endpoint POST /v2/cryptography/algorithms/range/components
- Added gRPC GetComponentVersionsInRange and REST endpoint GET /v2/cryptography/algorithms/versions/range/component
- Added gRPC GetComponentsVersionsInRange and REST endpoint POST /v2/cryptography/algorithms/versions/range/components
- Added gRPC GetComponentHintsInRange and REST endpoint GET /v2/cryptography/hints/component
- Added gRPC GetComponentsHintsInRange and REST endpoint POST /v2/cryptography/hints/components
- Added a method to handle response status on cryptography_service.go
- Implemented components request handler method
- Implemented component request handler
### Fixed
- Fixes linter issues
- Remove linter issues with deprecated methods

## [0.5.0] - 2025-09-04
### Changed
- Removed `/api` prefix from REST endpoints
### Updated
- Updated dependencies to latest version

## [0.4.2] - 2025-05-26
### Added 
- Added support to SQLite Database on env-setup.sh

### Fixed 
- Fixed .golangci.yml config file
- Fixed cognitive issues on GetCrypto and GetDetectionsInRange
- Fixed linter issues

### Changed
- Increased unit test coverage
- Upgraded Go runtime to version v1.24.0
- Upgraded project dependencies to latest

## [0.4.1] - 2025-02-07
### Added
- Include libraries

## [0.4.0] - 2025-01-30
### Added
- Detect cryptographic algorithms by specifying a purl and exact version
- Identify cryptographic algorithms across a Semver-compliant version range for a given purl
- Group versions  that do contain cryptographic algorithms and those do not within a specified purl version range
- Analyze usage patterns of Libraries/Frameworks/SDKs/Protocols within a specified purl version range

### Fixed
- Remove from list those versions that do not contain detections
- Detailed response status message.

[0.12.0]: https://github.com/scanoss/cryptography/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/scanoss/cryptography/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/scanoss/cryptography/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/scanoss/cryptography/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/scanoss/cryptography/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/scanoss/cryptography/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/scanoss/cryptography/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/scanoss/cryptography/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scanoss/cryptography/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/scanoss/cryptography/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/scanoss/cryptography/releases/tag/v0.4.1....v0.4.2
[0.4.1]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0...v0.4.1
[0.4.0]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0
