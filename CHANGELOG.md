# Changelog

## [Unreleased]
### Added
- Upcoming changes...

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

[0.7.1]: https://github.com/scanoss/cryptography/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/scanoss/cryptography/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scanoss/cryptography/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/scanoss/cryptography/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/scanoss/cryptography/releases/tag/v0.4.1....v0.4.2
[0.4.1]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0...v0.4.1
[0.4.0]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0