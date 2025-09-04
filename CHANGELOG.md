# Changelog

## [Unreleased]
### Added
- Upcoming changes...

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

[0.5.0]: https://github.com/scanoss/cryptography/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/scanoss/cryptography/releases/tag/v0.4.1....v0.4.2
[0.4.1]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0...v0.4.1
[0.4.0]: https://github.com/scanoss/cryptography/releases/tag/v0.4.0