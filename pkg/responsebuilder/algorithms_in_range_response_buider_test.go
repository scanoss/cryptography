package responsebuilder

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/papi/api/commonv2"
	"github.com/scanoss/papi/api/cryptographyv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"scanoss.com/cryptography/pkg/dtos"
)

// mockServerTransportStream implements grpc.ServerTransportStream for testing
type mockServerTransportStream struct {
	ctx context.Context
}

func (m *mockServerTransportStream) Method() string {
	return "test.method"
}

func (m *mockServerTransportStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SetTrailer(md metadata.MD) error {
	return nil
}

// TestCase represents a single test case loaded from CSV
type TestCase struct {
	Name                   string
	RequestJSON            string
	ExpectedStatusCode     string
	ExpectedStatusMessage  string
	ExpectedComponentCount int
	ComponentPurls         []string
	ComponentVersions      [][]string
	ComponentRequirements  []string
	ComponentAlgorithms    [][]*cryptographyv2.Algorithm
	ComponentErrorMessages []string
}

// loadTestCases loads test cases from a CSV file
func loadTestCases(t *testing.T, filename string) []TestCase {
	t.Helper()

	file, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open test cases file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV: %v", err)
	}

	if len(records) < 2 {
		t.Fatal("CSV file must have header and at least one test case")
	}

	// Skip header row
	var testCases []TestCase
	for _, record := range records[1:] {
		minColumns := 9
		if len(record) < minColumns {
			t.Fatalf("invalid CSV record (expected at least %d columns): %v", minColumns, record)
		}

		componentCount, err := strconv.Atoi(record[4])
		if err != nil {
			t.Fatalf("invalid component count: %v", record[4])
		}

		// Parse pipe-separated values for components
		purls := strings.Split(record[5], "|")
		versionsStr := strings.Split(record[6], "|")

		// Check if we have requirements field (new format)
		var requirementsStr []string
		var algorithmsStr []string
		var errorMessages []string

		if len(record) >= 10 {
			// New format with requirements
			requirementsStr = strings.Split(record[7], "|")
			algorithmsStr = strings.Split(record[8], "|")
			errorMessages = strings.Split(record[9], "|")
		} else {
			// Old format without requirements
			requirementsStr = make([]string, len(purls))
			algorithmsStr = strings.Split(record[7], "|")
			errorMessages = strings.Split(record[8], "|")
		}

		// Parse versions (semicolon-separated within each component)
		versions := make([][]string, len(versionsStr))
		for i, v := range versionsStr {
			if v != "" {
				versions[i] = strings.Split(v, ";")
			} else {
				versions[i] = []string{}
			}
		}

		// Parse algorithms (algorithm:strength format, semicolon-separated)
		algorithms := make([][]*cryptographyv2.Algorithm, len(algorithmsStr))
		for i, algStr := range algorithmsStr {
			algorithms[i] = []*cryptographyv2.Algorithm{}
			if algStr != "" {
				for _, alg := range strings.Split(algStr, ";") {
					parts := strings.Split(alg, ":")
					if len(parts) == 2 {
						algorithms[i] = append(algorithms[i], &cryptographyv2.Algorithm{
							Algorithm: parts[0],
							Strength:  parts[1],
						})
					}
				}
			}
		}

		testCases = append(testCases, TestCase{
			Name:                   record[0],
			RequestJSON:            record[1],
			ExpectedStatusCode:     record[2],
			ExpectedStatusMessage:  record[3],
			ExpectedComponentCount: componentCount,
			ComponentPurls:         purls,
			ComponentVersions:      versions,
			ComponentRequirements:  requirementsStr,
			ComponentAlgorithms:    algorithms,
			ComponentErrorMessages: errorMessages,
		})
	}

	return testCases
}

func TestInRangeResponseForMultipleComponents(t *testing.T) {
	// Create a mock server stream context
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	// Load test cases from CSV
	testCasesFile := filepath.Join("testdata", "algorithms_in_range_test_cases.csv")
	testCases := loadTestCases(t, testCasesFile)

	// Run all test cases
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Parse input
			var input dtos.CryptoInRangeOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse sample JSON: %v", err)
			}

			// Call the function under test
			res, err := ToComponentsAlgorithmsInRangeResponse(ctx, zlog.S, input)
			if err != nil {
				t.Errorf("unexpected error on creating response: %v", err)
				return
			}

			// Verify status
			expectedStatusCode := parseStatusCode(tc.ExpectedStatusCode)
			assert.Equal(t, tc.ExpectedStatusMessage, res.Status.Message, "status message mismatch")
			assert.Equal(t, expectedStatusCode, res.Status.Status, "status code mismatch")

			// Verify component count
			assert.Equal(t, tc.ExpectedComponentCount, len(res.Components), "component count mismatch")

			// Verify each component
			for i := 0; i < tc.ExpectedComponentCount && i < len(res.Components); i++ {
				component := res.Components[i]

				// Verify purl
				assert.Equal(t, tc.ComponentPurls[i], component.Purl, "purl mismatch at index %d", i)

				// Verify versions (handle nil vs empty slice)
				if len(tc.ComponentVersions[i]) == 0 && len(component.Versions) == 0 {
					// Both empty, consider equal
				} else {
					assert.Equal(t, tc.ComponentVersions[i], component.Versions, "versions mismatch at index %d", i)
				}

				// Verify algorithms (handle nil vs empty slice)
				if len(tc.ComponentAlgorithms[i]) == 0 && len(component.Algorithms) == 0 {
					// Both empty, consider equal
				} else {
					assert.Equal(t, tc.ComponentAlgorithms[i], component.Algorithms, "algorithms mismatch at index %d", i)
				}

				// Verify error message
				if tc.ComponentErrorMessages[i] != "" {
					assert.NotNil(t, component.ErrorMessage, "expected error message at index %d", i)
					if component.ErrorMessage != nil {
						assert.Equal(t, tc.ComponentErrorMessages[i], *component.ErrorMessage, "error message mismatch at index %d", i)
					}
				} else {
					if component.ErrorMessage != nil {
						assert.Empty(t, *component.ErrorMessage, "unexpected error message at index %d", i)
					}
				}
			}
		})
	}
}

// parseStatusCode converts string status code to commonv2.StatusCode
func parseStatusCode(code string) commonv2.StatusCode {
	switch code {
	case "SUCCESS":
		return commonv2.StatusCode_SUCCESS
	case "FAILED":
		return commonv2.StatusCode_FAILED
	case "SUCCEEDED_WITH_WARNINGS":
		return commonv2.StatusCode_SUCCEEDED_WITH_WARNINGS
	default:
		return commonv2.StatusCode_SUCCESS
	}
}

func TestToAlgorithmsInRangeResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	inputJSON := `{"purls":[{"purl":"pkg:github/scanoss/engine","requirement":">v5.4.5","versions":["v5.4.6","v5.4.7"],"algorithms":[{"algorithm":"SHA256","strength":"256"}],"status":{"status":"SUCCESS"}}]}`

	var input dtos.CryptoInRangeOutput
	err = json.Unmarshal([]byte(inputJSON), &input)
	if err != nil {
		t.Fatalf("failed to parse request JSON: %v", err)
	}

	res, err := ToAlgorithmsInRangeResponse(ctx, zlog.S, input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	assert.Equal(t, commonv2.StatusCode_SUCCESS, res.Status.Status)
	assert.Equal(t, "Algorithms in range retrieved successfully.", res.Status.Message)
	assert.Equal(t, 1, len(res.Purls))
	assert.Equal(t, "pkg:github/scanoss/engine", res.Purls[0].Purl)
	assert.Equal(t, []string{"v5.4.6", "v5.4.7"}, res.Purls[0].Versions)
}

func TestInRangeResponseForSingleComponent(t *testing.T) {
	// Create a mock server stream context
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	goodPurl := `{"purls": [
         {
            "purl": "pkg:github/scanoss/ldb",
            "requirement": ">v1.0.0",
            "versions": [
                "v1.0.1",
                "v1.0.2",
                "v1.0.3"
            ],
            "algorithms": [
                {
                    "algorithm": "MD5",
                    "strength": "16"
                }
            ]
        }
    ]}`

	var input dtos.CryptoInRangeOutput
	err = json.Unmarshal([]byte(goodPurl), &input)
	if err != nil {
		t.Fatalf("failed to parse sample JSON: %v", err)
	}

	// Call the function under test
	res, err := ToComponentAlgorithmsInRangeResponse(ctx, zlog.S, input)
	if err != nil {
		t.Errorf("unexpected error on creating response: %v", err)
		return
	}
	assert.Equal(t, res.Component.Purl, "pkg:github/scanoss/ldb")
	assert.Equal(t, res.Component.Versions, []string{"v1.0.1", "v1.0.2", "v1.0.3"})
	assert.Equal(t, res.Component.Algorithms, []*cryptographyv2.Algorithm{{Algorithm: "MD5", Strength: "16"}})
	assert.Equal(t, res.Status.Status, commonv2.StatusCode_SUCCESS)
	assert.Equal(t, res.Status.Message, "Algorithms in range retrieved successfully.")

	// ---------------------------------------------Purl without cryptography-------------------------------

	noCryptoJson := `{"purls": [
		         {
		            "purl": "pkg:github/scanoss/ldb",
		            "requirement": ">v1.0.0",
		            			"status": {
						"status": "NO_INFO",
						"message": "No crypto found",
						"error_message": ""
						}

		        }
		    ]}`

	var noCryptoInput dtos.CryptoInRangeOutput
	err = json.Unmarshal([]byte(noCryptoJson), &noCryptoInput)
	if err != nil {
		t.Fatalf("failed to parse sample JSON: %v", err)
	}
	noCryptoInput.Cryptography[0].Status.Error = cryptographyv2.ErrorCode_NO_INFO.Enum()
	noCryptoInput.Cryptography[0].Status.Status = dtos.ComponentWithoutInfo
	noCryptoInput.Cryptography[0].Status.Message = "No crypto found"

	// Call the function under test
	res, err = ToComponentAlgorithmsInRangeResponse(ctx, zlog.S, noCryptoInput)
	if err != nil {
		t.Errorf("unexpected error on creating response: %v", err)
		return
	}
	fmt.Printf("->%+v\n", res)
	assert.Equal(t, "pkg:github/scanoss/ldb", res.Component.Purl)
	assert.Equal(t, []*cryptographyv2.Algorithm{}, res.Component.Algorithms)
	assert.Equal(t, "No crypto found", res.Component.ErrorMessage)
	assert.Equal(t, *cryptographyv2.ErrorCode_NO_INFO.Enum(), res.Component.ErrorCode)
	assert.Equal(t, commonv2.StatusCode_SUCCESS, res.Status.Status)
	assert.Equal(t, "Algorithms in range retrieved successfully.", res.Status.Message)
	//--------------------------------------- Purl not found ------------------------------------

	noPurlJson := `{"purls": [
	         {
	            "purl": "pkg:github/scanoss/ldbo",
	            "requirement": ">v1.0.0",
	            			"status": {
					"status": "SUCCESS",
					"message": "purl not found"
					}

	        }
	    ]}`

	var noPurlInput dtos.CryptoInRangeOutput
	err = json.Unmarshal([]byte(noPurlJson), &noPurlInput)
	if err != nil {
		t.Fatalf("failed to parse sample JSON: %v", err)
	}
	noPurlInput.Cryptography[0].Status.Error = cryptographyv2.ErrorCode_COMPONENT_NOT_FOUND.Enum()
	noPurlInput.Cryptography[0].Status.Status = dtos.ComponentNotFound
	noPurlInput.Cryptography[0].Status.Message = "No crypto found"
	// Call the function under test
	res, err = ToComponentAlgorithmsInRangeResponse(ctx, zlog.S, noPurlInput)
	if err != nil {
		t.Errorf("unexpected error on creating response: %v", err)
		return
	}
	assert.Equal(t, res.Component.Purl, "pkg:github/scanoss/ldbo")
	assert.Equal(t, res.Component.Algorithms, []*cryptographyv2.Algorithm{})
	assert.Equal(t, res.Component.ErrorMessage, "No crypto found")
	assert.Equal(t, res.Component.ErrorCode, *cryptographyv2.ErrorCode_COMPONENT_NOT_FOUND.Enum())
	assert.Equal(t, res.Status.Status, commonv2.StatusCode_SUCCESS)
	assert.Equal(t, res.Status.Message, "Algorithms in range retrieved successfully.")
}
