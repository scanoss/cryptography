package responsebuilder

import (
	"fmt"
	pb "github.com/scanoss/papi/api/commonv2"
	"scanoss.com/cryptography/pkg/domain"
	"testing"
)

func TestStatuCodeToErrorCodeBuilder(t *testing.T) {

	tests := []struct {
		name     string
		input    domain.StatusCode
		expected *pb.ErrorCode
	}{
		{
			name:     "Should_Component_NoFound",
			input:    domain.ComponentNotFound,
			expected: pb.ErrorCode_COMPONENT_NOT_FOUND.Enum(),
		},
		{
			name:     "Should_ReturnInvalidPurl_WhenInputIsInvalidPurl",
			input:    domain.InvalidPurl,
			expected: pb.ErrorCode_INVALID_PURL.Enum(),
		},
		{
			name:     "Should_ReturnNoInfo_WhenInputIsComponentWithoutInfo",
			input:    domain.ComponentWithoutInfo,
			expected: pb.ErrorCode_NO_INFO.Enum(),
		},
		{
			name:     "Should_ReturnInvalidSemver_WhenInputIsInvalidSemver",
			input:    domain.InvalidSemver,
			expected: pb.ErrorCode_INVALID_SEMVER.Enum(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusCodeToErrorCode(tt.input)
			fmt.Printf("Result %v", result)
			fmt.Printf("Expected %v", tt.expected)
			// Handle nil cases
			if *result != *tt.expected {
				t.Errorf("Expected %v, received %v", *tt.expected, *result)
			}
		})
	}

}
