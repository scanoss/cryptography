package responsebuilder

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/scanoss/papi/api/commonv2"
	"github.com/scanoss/papi/api/cryptographyv2"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"scanoss.com/cryptography/pkg/dtos"
)

func TestAlgorithmsResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	testCasesFile := filepath.Join("testdata", "algorithms_response_test_cases.csv")
	testCases := loadTestCases(t, testCasesFile)

	for _, tc := range testCases {
		t.Run(tc.Name+"_ToAlgorithmResponse", func(t *testing.T) {
			var input dtos.CryptoOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToAlgorithmResponse(ctx, zlog.S, input)
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
				// ComponentVersions is [][]string, but we need just first element for non-range responses
				if len(tc.ComponentVersions[i]) > 0 {
					assert.Equal(t, tc.ComponentVersions[i][0], purl.Version)
				}

				if len(tc.ComponentAlgorithms[i]) == 0 && len(purl.Algorithms) == 0 {
					// Both empty
				} else {
					assert.Equal(t, tc.ComponentAlgorithms[i], purl.Algorithms)
				}

				if tc.ComponentErrorMessages[i] != "" {
					assert.NotNil(t, purl.ErrorMessage)
					if purl.ErrorMessage != nil {
						assert.Equal(t, tc.ComponentErrorMessages[i], *purl.ErrorMessage)
					}
				}
			}
		})

		t.Run(tc.Name+"_ToComponentsAlgorithmsResponse", func(t *testing.T) {
			var input dtos.CryptoOutput
			err := json.Unmarshal([]byte(tc.RequestJSON), &input)
			if err != nil {
				t.Fatalf("failed to parse request JSON: %v", err)
			}

			res, err := ToComponentsAlgorithmsResponse(ctx, zlog.S, input)
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
				// ComponentVersions is [][]string, but we need just first element for non-range responses
				if len(tc.ComponentVersions[i]) > 0 {
					assert.Equal(t, tc.ComponentVersions[i][0], component.Version)
				}
				assert.Equal(t, tc.ComponentRequirements[i], component.Requirement)

				if len(tc.ComponentAlgorithms[i]) == 0 && len(component.Algorithms) == 0 {
					// Both empty
				} else {
					assert.Equal(t, tc.ComponentAlgorithms[i], component.Algorithms)
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

func TestComponentAlgorithmsResponse(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	singleComponentJSON := `{"purls":[{"purl":"pkg:github/scanoss/engine","version":"v5.4.5","requirement":">=v5.4.0","algorithms":[{"algorithm":"SHA256","strength":"256"}],"status":{"status":"SUCCESS"}}]}`

	var input dtos.CryptoOutput
	err = json.Unmarshal([]byte(singleComponentJSON), &input)
	if err != nil {
		t.Fatalf("failed to parse request JSON: %v", err)
	}

	res, err := ToComponentAlgorithmsResponse(ctx, zlog.S, input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	assert.Equal(t, "Algorithms retrieved successfully.", res.Status.Message)
	assert.Equal(t, commonv2.StatusCode_SUCCESS, res.Status.Status)
	assert.Equal(t, "pkg:github/scanoss/engine", res.Component.Purl)
	assert.Equal(t, "v5.4.5", res.Component.Version)
	assert.Equal(t, ">=v5.4.0", res.Component.Requirement)
	assert.Equal(t, []*cryptographyv2.Algorithm{{Algorithm: "SHA256", Strength: "256"}}, res.Component.Algorithms)
}

func TestAlgorithmsResponseNilInput(t *testing.T) {
	ctx := grpc.NewContextWithServerTransportStream(
		context.Background(),
		&mockServerTransportStream{ctx: context.Background()},
	)

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	emptyInput := dtos.CryptoOutput{Cryptography: nil}

	_, err = ToAlgorithmResponse(ctx, zlog.S, emptyInput)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cryptography found")

	_, err = ToComponentsAlgorithmsResponse(ctx, zlog.S, emptyInput)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cryptography found")

	_, err = ToComponentAlgorithmsResponse(ctx, zlog.S, emptyInput)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cryptography found")
}
