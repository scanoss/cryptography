package utils

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// IsValidRequirement validates whether a version requirement string contains valid semantic version constraints.
// It accepts comma-separated constraints with comparison operators (>, <, >=, <=, ~, ^).
// Each constraint must contain a valid semantic version after the operator.
// Returns true if all constraints are valid, false otherwise.
func IsValidRequirement(requirement string) bool {
	constraints := strings.Split(requirement, ",")

	for _, constraint := range constraints {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			return false
		}

		// Extract the version part by removing comparison operators
		version := constraint
		version = strings.TrimLeft(version, "><=~^")
		version = strings.TrimSpace(version)
		version = strings.TrimLeft(version, "v")

		// Validate it's a proper semver
		_, err := semver.StrictNewVersion(version)
		if err != nil {
			return false
		}
	}
	return true
}
