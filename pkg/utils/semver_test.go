package utils

import (
	"testing"
)

func TestIsValidRequirement(t *testing.T) {
	tests := []struct {
		name        string
		requirement string
		expected    bool
	}{
		// Valid single constraints
		{
			name:        "valid version with greater than",
			requirement: ">1.0.0",
			expected:    true,
		},
		{
			name:        "valid version with less than",
			requirement: "<2.0.0",
			expected:    true,
		},
		{
			name:        "valid version with greater than or equal",
			requirement: ">=1.5.0",
			expected:    true,
		},
		{
			name:        "valid version with less than or equal",
			requirement: "<=3.0.0",
			expected:    true,
		},
		{
			name:        "valid version with tilde",
			requirement: "~1.2.3",
			expected:    true,
		},
		{
			name:        "valid version with caret",
			requirement: "^1.2.3",
			expected:    true,
		},
		{
			name:        "valid version with v prefix",
			requirement: ">v1.0.0",
			expected:    true,
		},
		{
			name:        "valid version without operator",
			requirement: "1.0.0",
			expected:    true,
		},

		// Valid multiple constraints
		{
			name:        "valid multiple constraints",
			requirement: ">=1.0.0, <2.0.0",
			expected:    true,
		},
		{
			name:        "valid multiple constraints with v prefix",
			requirement: ">=v1.0.0, <v2.0.0",
			expected:    true,
		},

		// Invalid constraints
		{
			name:        "empty string",
			requirement: "",
			expected:    false,
		},
		{
			name:        "invalid version format",
			requirement: ">invalid.version",
			expected:    false,
		},
		{
			name:        "invalid semantic version",
			requirement: ">1.0",
			expected:    false,
		},
		{
			name:        "version with invalid characters",
			requirement: ">1.0.0-alpha!",
			expected:    false,
		},
		{
			name:        "empty constraint in multiple",
			requirement: ">=1.0.0, , <2.0.0",
			expected:    false,
		},
		{
			name:        "one invalid constraint in multiple",
			requirement: ">=1.0.0, >invalid, <2.0.0",
			expected:    false,
		},
		{
			name:        "only spaces",
			requirement: "   ",
			expected:    false,
		},
		{
			name:        "only operators without version",
			requirement: ">=",
			expected:    false,
		},

		// Edge cases
		{
			name:        "version with pre-release",
			requirement: ">1.0.0-alpha",
			expected:    true,
		},
		{
			name:        "version with build metadata",
			requirement: ">1.0.0+build.1",
			expected:    true,
		},
		{
			name:        "version with both pre-release and build",
			requirement: ">1.0.0-alpha+build.1",
			expected:    true,
		},
		{
			name:        "multiple constraints with extra spaces",
			requirement: " >= 1.0.0 , < 2.0.0 ",
			expected:    true,
		},
		{
			name:        "version with multiple pre-release identifiers",
			requirement: ">1.0.0-alpha.1.2",
			expected:    true,
		},
		{
			name:        "version with numeric pre-release",
			requirement: ">1.0.0-123",
			expected:    true,
		},
		{
			name:        "version with complex build metadata",
			requirement: ">1.0.0+20130313144700",
			expected:    true,
		},
		{
			name:        "major version zero",
			requirement: ">=0.1.0",
			expected:    true,
		},
		{
			name:        "patch version zero",
			requirement: ">=1.0.0",
			expected:    true,
		},
		{
			name:        "all zeros version",
			requirement: ">=0.0.0",
			expected:    true,
		},
		{
			name:        "version with v prefix and tilde",
			requirement: "~v1.2.3",
			expected:    true,
		},
		{
			name:        "version with v prefix and caret",
			requirement: "^v1.2.3",
			expected:    true,
		},
		{
			name:        "multiple constraints with mixed operators",
			requirement: ">=1.0.0, <=2.0.0, >1.5.0",
			expected:    true,
		},
		{
			name:        "three part constraint",
			requirement: ">=1.0.0, <2.0.0, >=1.5.0",
			expected:    true,
		},
		{
			name:        "constraint with leading comma",
			requirement: ",>=1.0.0",
			expected:    false,
		},
		{
			name:        "constraint with trailing comma",
			requirement: ">=1.0.0,",
			expected:    false,
		},
		{
			name:        "version without minor and patch",
			requirement: ">1",
			expected:    false,
		},
		{
			name:        "version without patch",
			requirement: ">1.0",
			expected:    false,
		},
		{
			name:        "version with letters in numbers",
			requirement: ">1.a.0",
			expected:    false,
		},
		{
			name:        "version with negative numbers",
			requirement: ">-1.0.0",
			expected:    false,
		},
		{
			name:        "constraint with only tilde",
			requirement: "~",
			expected:    false,
		},
		{
			name:        "constraint with only caret",
			requirement: "^",
			expected:    false,
		},
		{
			name:        "large version numbers",
			requirement: ">=999.999.999",
			expected:    true,
		},
		{
			name:        "version with dots only",
			requirement: ">...",
			expected:    false,
		},
		{
			name:        "multiple operators without spaces",
			requirement: ">=1.0.0,<=2.0.0,>1.5.0",
			expected:    true,
		},
		{
			name:        "version with pre-release and multiple constraints",
			requirement: ">=1.0.0-alpha, <2.0.0-beta",
			expected:    true,
		},
		{
			name:        "single digit with v prefix",
			requirement: "v1.0.0",
			expected:    true,
		},
		{
			name:        "constraint with multiple v prefixes in list",
			requirement: ">=v1.0.0, <v2.0.0, >=v1.5.0",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidRequirement(tt.requirement)
			if result != tt.expected {
				t.Errorf("IsValidRequirement(%q) = %v, expected %v", tt.requirement, result, tt.expected)
			}
		})
	}
}
