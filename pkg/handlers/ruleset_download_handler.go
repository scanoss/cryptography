// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/httphelper"
	"scanoss.com/cryptography/pkg/usecase"
)

// RulesetDownloadHandler handles gRPC requests for downloading cryptography detection rulesets.
type RulesetDownloadHandler struct {
	rulesetDownloadUseCase *usecase.RulesetDownloadUseCase
	config                 *myconfig.ServerConfig
}

// NewRulesetDownloadHandler creates a new RulesetDownloadHandler instance.
//
// This constructor initializes the handler with a ruleset download use case that provides
// access to the filesystem for serving ruleset tarballs.
//
// Parameters:
//   - config: Server configuration including ruleset storage path
//
// Returns:
//   - *RulesetDownloadHandler: Initialized handler ready to process requests
func NewRulesetDownloadHandler(config *myconfig.ServerConfig) *RulesetDownloadHandler {
	return &RulesetDownloadHandler{
		config:                 config,
		rulesetDownloadUseCase: usecase.NewRulesetDownload(config),
	}
}

// DownloadRuleset handles the download request for a specific ruleset version.
//
// This method processes a RulesetDownloadRequest containing the ruleset name and version
// (which can be "latest" or a specific version like "v1.2.3"). It validates the request,
// resolves the version, reads the metadata and tarball from the filesystem, and returns
// the tarball as a binary response with appropriate HTTP headers.
//
// The response includes custom headers:
//   - Content-Type: application/gzip
//   - Content-Disposition: attachment; filename="..."
//   - SCANOSS-Ruleset-Name: Name of the ruleset
//   - SCANOSS-Ruleset-Version: Resolved version number
//   - SCANOSS-Ruleset-Created-At: Creation timestamp of the ruleset
//   - SCANOSS-Ruleset-Description: Description of the ruleset (if present)
//   - X-Checksum-SHA256: SHA256 checksum of the tarball
//
// Parameters:
//   - ctx: Request context containing logger and trace information
//   - request: RulesetDownloadRequest with ruleset name and version
//
// Returns:
//   - *httpbody.HttpBody: Binary response containing the tarball
//   - error: gRPC error with appropriate status code (NotFound, InvalidArgument, Internal)
func (r *RulesetDownloadHandler) DownloadRuleset(ctx context.Context, request *pb.RulesetDownloadRequest) (*httpbody.HttpBody, error) {
	requestStartTime := time.Now()
	s := ctxzap.Extract(ctx).Sugar()
	s.Infof("Processing ruleset download request: %s/%s", request.RulesetName, request.Version)

	if err := r.validateRequest(request); err != nil {
		s.Warnf("Invalid ruleset download request: %v", err)
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusBadRequest)
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	ruleset, err := r.rulesetDownloadUseCase.DownloadRuleset(ctx, s, request.RulesetName, request.Version)
	if err != nil {
		return r.handleUseCaseError(ctx, s, err)
	}

	filename := fmt.Sprintf("%s-%s.tar.gz", ruleset.Metadata.Name, ruleset.Metadata.Version)
	headers := []string{
		"content-type", "application/gzip",
		"content-disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename),
		"scanoss-ruleset-name", ruleset.Metadata.Name,
		"scanoss-ruleset-version", ruleset.Metadata.Version,
		"scanoss-ruleset-created-at", ruleset.Metadata.CreatedAt,
		"x-checksum-sha256", ruleset.Metadata.ChecksumSHA256,
	}

	if strings.TrimSpace(ruleset.Metadata.Description) != "" {
		headers = append(headers, "scanoss-ruleset-description", ruleset.Metadata.Description)
	}

	md := metadata.Pairs(headers...)

	if err := grpc.SendHeader(ctx, md); err != nil {
		s.Errorf("Failed to send response headers: %v", err)
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusInternalServerError)
		return nil, status.Errorf(codes.Internal, "failed to send response headers")
	}

	response := &httpbody.HttpBody{
		ContentType: "application/gzip",
		Data:        ruleset.TarballData,
	}

	telemetryDownloadRulesetRequestTime(ctx, r.config, requestStartTime)
	telemetryAddRulesetDownloaded(ctx, r.config)

	s.Infof("Successfully served ruleset: %s/%s (%d bytes)", request.RulesetName, request.Version, len(ruleset.TarballData))
	return response, nil
}

// validateRequest validates the RulesetDownloadRequest.
func (r *RulesetDownloadHandler) validateRequest(request *pb.RulesetDownloadRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be empty")
	}

	if strings.TrimSpace(request.RulesetName) == "" {
		return fmt.Errorf("ruleset_name cannot be empty")
	}

	if strings.TrimSpace(request.Version) == "" {
		return fmt.Errorf("version cannot be empty, you must provide a specific version or 'latest'")
	}

	version := strings.TrimSpace(request.Version)
	_, err := semver.NewVersion(version)
	if err != nil && version != "latest" {
		return fmt.Errorf("version must be 'latest' or a valid semver string (e.g., 'v1.2.3')")
	}

	return nil
}

// handleUseCaseError converts use case errors to appropriate gRPC errors with HTTP status codes.
func (r *RulesetDownloadHandler) handleUseCaseError(ctx context.Context, s *zap.SugaredLogger, err error) (*httpbody.HttpBody, error) {
	errMsg := err.Error()

	s.Errorf("Error while downloading ruleset: %v", err)

	switch {
	case strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist"):
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusNotFound)
		return nil, status.Errorf(codes.NotFound, "requested ruleset or version not found")
	case strings.Contains(errMsg, "integrity check failed") || strings.Contains(errMsg, "checksum"):
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusInternalServerError)
		return nil, status.Errorf(codes.DataLoss, "ruleset integrity verification failed")
	default:
		httphelper.SetHTTPCodeOnTrailer(ctx, s, http.StatusInternalServerError)
		return nil, status.Errorf(codes.Internal, "internal server error")
	}
}
