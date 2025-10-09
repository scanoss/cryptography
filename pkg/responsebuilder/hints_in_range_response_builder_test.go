package responsebuilder

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/papi/api/commonv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"scanoss.com/cryptography/pkg/dtos"
)

type HintsInRangeTestCase struct {
	Name                   string
	RequestJSON            string
	ExpectedStatusCode     string
	ExpectedStatusMessage  string
	ExpectedComponentCount int
	ComponentPurls         []string
	ComponentVersions      []string
	ComponentHintsCount    []int
	ComponentErrorMessages []string
}

func loadHintsInRangeTestCases(t *testing.T, filename string) []HintsInRangeTestCase {
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

	var testCases []HintsInRangeTestCase
	for _, record := range records[1:] {
		if len(record) < 9 {
			t.Fatalf("invalid CSV record: %v", record)
		}

		componentCount, err := strconv.Atoi(record[4])
		if err != nil {
			t.Fatalf("invalid component count: %v", record[4])
		}

		purls := strings.Split(record[5], "|")
		versions := strings.Split(record[6], "|")
		hintsCountStr := strings.Split(record[7], "|")
		errorMessages := strings.Split(record[8], "|")

		hintsCounts := make([]int, len(hintsCountStr))
		for i, hc := range hintsCountStr {
			count, err := strconv.Atoi(hc)
			if err != nil {
				t.Fatalf("invalid hints count: %v", hc)
			}
			hintsCounts[i] = count
		}

		testCases = append(testCases, HintsInRangeTestCase{
			Name:                   record[0],
			RequestJSON:            record[1],
			ExpectedStatusCode:     record[2],
			ExpectedStatusMessage:  record[3],
			ExpectedComponentCount: componentCount,
			ComponentPurls:         purls,
			ComponentVersions:      versions,
			ComponentHintsCount:    hintsCounts,
			ComponentErrorMessages: errorMessages,
		})
	}

	return testCases
}

func TestHintsInRangeResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	testCasesFile := filepath.Join("testdata", "hints_in_range_test_cases.csv")
	testCases := loadHintsInRangeTestCases(t, testCasesFile)

	for _, tc := range testCases {
		t.Run(tc.Name+"_ToHintsInRangeResponse", func(t *testing.T) {
			var input dtos.ECOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToHintsInRangeResponse(ctx, zlog.S, input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			assert.Equal(t, tc.ExpectedComponentCount, len(res.Purls))

			for i := 0; i < tc.ExpectedComponentCount && i < len(res.Purls); i++ {
				purl := res.Purls[i]
				assert.Equal(t, tc.ComponentPurls[i], purl.Purl)

				// Parse versions from CSV format
				expectedVersions := []string{}
				if tc.ComponentVersions[i] != "" {
					expectedVersions = strings.Split(tc.ComponentVersions[i], ";")
				}
				assert.Equal(t, expectedVersions, purl.Versions)
				assert.Equal(t, tc.ComponentHintsCount[i], len(purl.Hints))

				if tc.ComponentErrorMessages[i] != "" {
					assert.NotNil(t, purl.ErrorMessage)
					if purl.ErrorMessage != nil {
						assert.Equal(t, tc.ComponentErrorMessages[i], *purl.ErrorMessage)
					}
				}
			}
		})

		t.Run(tc.Name+"_ToComponentsHintsInRangeResponse", func(t *testing.T) {
			var input dtos.ECOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToComponentsHintsInRangeResponse(ctx, zlog.S, input)
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
				expectedVersions := []string{}
				if tc.ComponentVersions[i] != "" {
					expectedVersions = strings.Split(tc.ComponentVersions[i], ";")
				}
				assert.Equal(t, expectedVersions, component.Versions)
				assert.Equal(t, tc.ComponentHintsCount[i], len(component.Hints))

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

func TestComponentHintsInRangeResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	singleComponentJSON := `{"purls":[{"purl":"pkg:github/scanoss/engine","versions":["v5.4.6","v5.4.7"],"hints":[{"id":"1","name":"AES","purl":"pkg:crypto/aes","description":"AES encryption","category":"symmetric","url":"https://example.com/aes"}],"status":{"status":"SUCCESS"}}]}`

	var input dtos.ECOutput
	err = json.Unmarshal([]byte(singleComponentJSON), &input)
	if err != nil {
		t.Fatalf("failed to parse request JSON: %v", err)
	}

	res, err := ToComponentHintsInRangeResponse(ctx, zlog.S, input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	assert.Equal(t, "Hints in range retrieved successfully.", res.Status.Message)
	assert.Equal(t, commonv2.StatusCode_SUCCESS, res.Status.Status)
	assert.Equal(t, "pkg:github/scanoss/engine", res.Component.Purl)
	assert.Equal(t, []string{"v5.4.6", "v5.4.7"}, res.Component.Versions)
	assert.Equal(t, 1, len(res.Component.Hints))
	assert.Equal(t, "1", res.Component.Hints[0].Id)
	assert.Equal(t, "AES", res.Component.Hints[0].Name)
}
