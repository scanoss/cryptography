# Changelog

## [Unreleased]

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
