package responsebuilder

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"scanoss.com/cryptography/pkg/domain"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type VersionsTestCase struct {
	Name                   string
	RequestJSON            string
	ExpectedStatusCode     string
	ExpectedStatusMessage  string
	ExpectedComponentCount int
	ComponentPurls         []string
	VersionsWith           []string
	VersionsWithout        []string
	ComponentErrorMessages []string
}

func loadVersionsTestCases(t *testing.T, filename string) []VersionsTestCase {
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

	var testCases []VersionsTestCase
	for _, record := range records[1:] {
		if len(record) < 9 {
			t.Fatalf("invalid CSV record: %v", record)
		}

		componentCount, err := strconv.Atoi(record[4])
		if err != nil {
			t.Fatalf("invalid component count: %v", record[4])
		}

		purls := strings.Split(record[5], "|")
		versionsWith := strings.Split(record[6], "|")
		versionsWithout := strings.Split(record[7], "|")
		errorMessages := strings.Split(record[8], "|")

		testCases = append(testCases, VersionsTestCase{
			Name:                   record[0],
			RequestJSON:            record[1],
			ExpectedStatusCode:     record[2],
			ExpectedStatusMessage:  record[3],
			ExpectedComponentCount: componentCount,
			ComponentPurls:         purls,
			VersionsWith:           versionsWith,
			VersionsWithout:        versionsWithout,
			ComponentErrorMessages: errorMessages,
		})
	}

	return testCases
}

func TestVersionsInRangeResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	testCasesFile := filepath.Join("testdata", "versions_in_range_test_cases.csv")
	testCases := loadVersionsTestCases(t, testCasesFile)

	for _, tc := range testCases {
		t.Run(tc.Name+"_ToVersionsInRangeResponse", func(t *testing.T) {
			var input domain.VersionsInRangeOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToVersionsInRangeResponse(ctx, zlog.S, input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			expectedStatusCode := parseStatusCode(tc.ExpectedStatusCode)
			assert.Equal(t, tc.ExpectedStatusMessage, res.Status.Message)
			assert.Equal(t, expectedStatusCode, res.Status.Status)
			assert.Equal(t, tc.ExpectedComponentCount, len(res.Purls))

			for i := 0; i < tc.ExpectedComponentCount && i < len(res.Purls); i++ {
				purl := res.Purls[i]
				assert.Equal(t, tc.ComponentPurls[i], purl.Purl)

				// Parse versions from CSV format
				expectedVersionsWith := []string{}
				if tc.VersionsWith[i] != "" {
					expectedVersionsWith = strings.Split(tc.VersionsWith[i], ";")
				}
				expectedVersionsWithout := []string{}
				if tc.VersionsWithout[i] != "" {
					expectedVersionsWithout = strings.Split(tc.VersionsWithout[i], ";")
				}

				if len(expectedVersionsWith) == 0 && len(purl.VersionsWith) == 0 {
					// Both empty
				} else {
					assert.Equal(t, expectedVersionsWith, purl.VersionsWith)
				}

				if len(expectedVersionsWithout) == 0 && len(purl.VersionsWithout) == 0 {
					// Both empty
				} else {
					assert.Equal(t, expectedVersionsWithout, purl.VersionsWithout)
				}

				if tc.ComponentErrorMessages[i] != "" {
					assert.NotNil(t, purl.ErrorMessage)
					if purl.ErrorMessage != nil {
						assert.Equal(t, tc.ComponentErrorMessages[i], *purl.ErrorMessage)
					}
				}
			}
		})

		t.Run(tc.Name+"_ToComponentsVersionsInRangeResponse", func(t *testing.T) {
			var input domain.VersionsInRangeOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToComponentsVersionsInRangeResponse(ctx, zlog.S, input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			expectedStatusCode := parseStatusCode(tc.ExpectedStatusCode)
			assert.Equal(t, tc.ExpectedStatusMessage, res.Status.Message)
			assert.Equal(t, expectedStatusCode, res.Status.Status)
			assert.Equal(t, tc.ExpectedComponentCount, len(res.Components))

			for i := 0; i < tc.ExpectedComponentCount && i < len(res.Components); i++ {
				component := res.Components[i]
				assert.Equal(t, tc.ComponentPurls[i], component.Purl)

				// Parse versions from CSV format
				expectedVersionsWith := []string{}
				if tc.VersionsWith[i] != "" {
					expectedVersionsWith = strings.Split(tc.VersionsWith[i], ";")
				}
				expectedVersionsWithout := []string{}
				if tc.VersionsWithout[i] != "" {
					expectedVersionsWithout = strings.Split(tc.VersionsWithout[i], ";")
				}

				if len(expectedVersionsWith) == 0 && len(component.VersionsWith) == 0 {
					// Both empty
				} else {
					assert.Equal(t, expectedVersionsWith, component.VersionsWith)
				}

				if len(expectedVersionsWithout) == 0 && len(component.VersionsWithout) == 0 {
					// Both empty
				} else {
					assert.Equal(t, expectedVersionsWithout, component.VersionsWithout)
				}

				if tc.ComponentErrorMessages[i] != "" {
					assert.NotNil(t, component.ErrorMessage)
					if component.ErrorMessage != nil {
						assert.Equal(t, tc.ComponentErrorMessages[i], *component.ErrorMessage)
					}
				}
			}
		})
	}
}

func TestComponentVersionsInRangeResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	singleComponentJSON := `{"purls":[{"purl":"pkg:github/scanoss/engine","versions_with":["v5.4.6","v5.4.7"],"versions_without":["v5.4.5"],"status":{"status":"SUCCESS"}}]}`

	var input domain.VersionsInRangeOutput
	err = json.Unmarshal([]byte(singleComponentJSON), &input)
	if err != nil {
		t.Fatalf("failed to parse request JSON: %v", err)
	}

	res, err := ToComponentVersionsInRangeResponse(ctx, zlog.S, input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	assert.Equal(t, "Versions in range retrieved successfully.", res.Status.Message)
	assert.Equal(t, commonv2.StatusCode_SUCCESS, res.Status.Status)
	assert.Equal(t, "pkg:github/scanoss/engine", res.Component.Purl)
	assert.Equal(t, []string{"v5.4.6", "v5.4.7"}, res.Component.VersionsWith)
	assert.Equal(t, []string{"v5.4.5"}, res.Component.VersionsWithout)
}

func TestComponentVersionsInRangeResponseNilInput(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	emptyInput := domain.VersionsInRangeOutput{Versions: nil}

	_, err = ToComponentVersionsInRangeResponse(ctx, zlog.S, emptyInput)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions found")
}
