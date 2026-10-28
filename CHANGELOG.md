# Changelog

## [Unreleased]

## [0.14.0] - 2026-10-28
### Added
- **The serving database is reloaded on `SIGHUP`** (`systemctl reload`). Production rotates the export daily by repointing the `full.duckdb` symlink, and a running process kept reading the file it had opened - serving the previous day's data, and holding the space of the file once the rotation deleted it - until it was restarted. On `SIGHUP` the service resolves `Database.Path` again and, when it names another file, opens that file read-only, checks that it answers and carries every table the file in use carries, and swaps it in. Requests already running finish on the previous file, which is closed with its last connection; idle connections to it are closed at once. A file that fails the checks is rejected, logged, and the current one stays in use. An unchanged path is a no-op. The other drivers are not reloaded, and the signal no longer terminates the process, which was Go's default
- The systemd unit declares `ExecReload` and `ReloadPropagatedFrom=scanoss-services-api.service`: the rotation already reloads `scanoss-services-api` after repointing the symlink, and that reload now reaches this service too

## [0.13.2] - 2026-10-27

### Fixed
- **The release workflow fails to build.** Since 0.13.1 it runs in a `golang:1.25-bookworm` container as root, over a checkout the runner owns, and git refuses such a repository, so the build could not read the version from the tag and the build stopped. The workflow now marks the workspace as a safe directory. 0.13.1 was tagged but never released

## [0.13.1] - 2026-10-27

### Fixed
- **The 0.13.0 binaries and Docker image do not start on Debian bookworm.** The DuckDB driver made the build cgo, so the binary links against glibc, and both builds ran on a newer one than the bookworm runtime: the release on `ubuntu-latest` and the image on `golang:1.25`, now Debian 13. They require `GLIBC_2.38` and bookworm has 2.36, so they failed at startup with "version `GLIBC_2.38' not found". The release now builds in a `golang:1.25-bookworm` container and the Dockerfile's build stage uses the same image; the binaries require glibc 2.34 at most

## [0.13.0] - 2026-10-27

### Security
- **Hardened against an unimplemented method killing the server.** The service embedded the papi `CryptographyServer` *interface* rather than the generated `UnimplementedCryptographyServer`. The interface value is nil, so any method the service does not implement would dereference it and panic, taking the whole process down. Every method of the current papi interface is implemented, so nothing reaches it today - but the first method papi adds would, silently, as a remotely reachable crash. scanoss/components shipped exactly that: `GetComponentStatistics` arrived in papi v0.42.0, was never implemented, and one unauthenticated request killed the server
- Upgraded `google.golang.org/grpc` to v1.83.1, `golang.org/x/net` to v0.57.0 and the OpenTelemetry modules (`otel`, `otel/sdk`, `otlptrace`, `otlptracegrpc`) to v1.45.0 to fix open Dependabot security advisories
- `go-grpc-helper` v0.16.0 → v0.17.0. A failed REST call no longer answers `200` with an empty, unparseable body when the handler set no `x-http-code` trailer: the gateway now falls back to the standard grpc-gateway error response, and gRPC status codes map to their HTTP equivalent, so `Unimplemented` is `501` rather than `500`

### Changed
- **The service now reads the serving knowledge base instead of the mining database.** The mining path is gone; there is no configuration that selects it. Endpoint routes and response shapes are unchanged
- **Cryptography is keyed by `(purl_id, version)` rather than by `url_hash`.** The mining lookup went purl → `all_urls` → `package_hash` → `component_crypto`; the hash was the identity of a package archive, and resolving it needed a join through `all_urls`, `mines` and `versions`. The serving schema records crypto against the component version directly, so the hash round-trip is gone
- Algorithms read `component_version_crypto ⋈ crypto_algorithm`, taking both the name and the strength from the catalogue; crypto-library hints read `component_version_crypto_library ⋈ crypto_library` (the renamed `crypto_libraries`)
- The IN-lists are bound parameters now. The mining queries built them by interpolating the values into the SQL string
- Component and version resolution no longer goes through `go-component-helper`, which resolves against `all_urls`, `mines` and `versions` - none of which exist in the serving schema. It is replaced by `pkg/resolver`, over `component` / `component_version`
- **The source-purl fallback now follows `component.source_purl_id`** instead of the mining `projects` table's source-mine columns. Its behaviour is unchanged: a component with no cryptographic information is retried against the repository it was built from, and the result carries `info_code: WARNING` naming the source purl
- The range endpoints filter the resolved component's own version set instead of a set of `all_urls` rows, so there is no purl type left to re-check: the resolution has already pinned one component
- An exact version now matches whether or not it carries a leading `v` (`5.4.7` finds `v5.4.7`), answering with the spelling the component publishes. The mining lookup did this through `SemverTogglePrefix`; the resolver reproduces it
- Binaries are built with `CGO_ENABLED=1`, and the runtime image moved to `debian:bookworm-slim` with `libstdc++6`. The DuckDB driver is a cgo binding, so a pure-Go build can no longer be produced
- A source link that points back at the component itself (11.4 of 13.9 million) is no longer followed. It cost an unindexed full scan of `component`, about 2.5 s of CPU, for a fallback that could only repeat the lookup

### Added
- **DuckDB support**, the intended production backend for the serving knowledge base. Set `DB_DRIVER=duckdb` and `DB_PATH` to the serving file, which is opened read-only
- `pkg/db`, opening the serving database for any of duckdb, sqlite or postgres
- `pkg/resolver`, the serving component resolution and the shared source-purl fallback
- `pkg/models/test_schema.go`, holding the serving schema the tests build their database from. The fixtures under `tests/` used to carry their own `CREATE TABLE` statements, each describing the table as that fixture's author imagined it

### Removed
- `pkg/models/all_urls.go`. Nothing resolves through package hashes any more
- `StrengthFromKeySizes`, and the `SPDX_crypto_algorithm` join it fed. The catalogue stores the strength

### Deployment
- **Breaking:** requires a serving knowledge base. Point `DB_PATH` at the `.duckdb` file and set `DB_DRIVER=duckdb`
- **The algorithm catalogue changed shape, and the service follows it.** `crypto_algorithm` was `(id, name)` with the short name in `name`; it is now `(id, name, category, strength, spdx_id)` with the short name in `id` and a long description in `name`. A query selecting `name` returns "Advanced Encryption Standard" where the API contract wants "aes", so the algorithm name is read from `id`
- **`strength` is read, not derived.** An earlier revision of this branch derived it from the SPDX key sizes because the export carried no strength column. It carries one now, and its 219 `(algorithm, strength)` pairs are identical to mining's - serving normalises mining's `-` to empty for 11 algorithms, and that is the only difference. The SPDX derivation resolved for 118 of the 219 and disagreed where it did: it made `aes` "256" against mining's "128-256", and `des` "168-56". The SPDX join is gone, and with it `StrengthFromKeySizes`
- **The earlier crypto blocker is resolved.** It was measured against mining's `component_crypto`, a table mining has since superseded with `component_has_crypto` + `crypto_algorithm`. The export now mirrors mining's current model exactly: both hold 219 algorithms, 18 tags and 659 tag assignments, and the 219 identifiers are identical. `sha1`/`sha2`/`sha3` and `chacha20` are separate entries, so the collapse into `shax`/`chacha` is gone
  - Of the 224 names in mining's superseded table, 5 have no entry: `shax` and `tdes`, `rsa-oaep`, `X509` and `diffiehellman`. They are legacy spellings, and together they are 1,583,924 of 346,118,833 rows - **0.46%**
  - Measured per component, `pkg:github/galoisinc/hacrypto` at `5c99d7a` reports 154 algorithms from serving against mining's 154
  - The earlier figures in this file (33.7% unrepresented, 17.2% collapsed, openssl 102 against 52) were wrong twice over: they compared against the superseded table, and they reached it by joining `component_crypto.url_hash` to `all_urls.url_hash`, where the key is actually `all_urls.package_hash`
- **Not exposed:** `crypto_algorithm.category`, `crypto_algorithm_tag` and `crypto_algorithm_has_tag` are in the export and have no field in the papi contract
- Version strings can change for a given component: serving normalises them, so openssl's `OpenSSL_1_1_1a` is `1.0.1-s` there
- Verified against the production serving file (72.6 GiB): every endpoint, single and batch, including the source-purl fallback and the per-version range breakdown. The algorithm read was re-verified against the updated schema after the catalogue change
- `make build_arm` now cross-compiles with cgo and needs an `aarch64` toolchain (set `CC`); the amd64 build is unaffected

### Fixed
- **Scoped npm packages, and other purls the export stores encoded or with qualifiers, resolve again.** `component.purl` keeps scoped npm and jsr names percent-encoded (`pkg:npm/%40angular/core`), qualifiers on generic, conda and cran keys, and a raw `+` in some rpm and deb names. The resolver decoded the purl and rebuilt the key, so 1.96 million components (6%) - plus 1.6 million qualified ones - answered `COMPONENT_NOT_FOUND` however they were spelled. It now tries the caller's spelling, the canonical rendering and the decoded form in one indexed lookup
- **A scoped purl is no longer split at its namespace `@`.** `buildComponentDTO` split on the first `@`, so `pkg:npm/@angular/core` became the purl `pkg:npm/` and was answered `INVALID_PURL`. Pre-existing on main

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

[0.14.0]: https://github.com/scanoss/cryptography/compare/v0.13.2...v0.14.0
[0.13.2]: https://github.com/scanoss/cryptography/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/scanoss/cryptography/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/scanoss/cryptography/compare/v0.12.0...v0.13.0
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
