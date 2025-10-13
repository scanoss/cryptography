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

// Package service implements the gRPC service endpoints
package service

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	common "github.com/scanoss/papi/api/commonv2"
	pb "github.com/scanoss/papi/api/cryptographyv2"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/handlers"
)

// cryptographyServer implements the gRPC CryptographyServer interface.
// It handles requests for cryptographic algorithm information, version ranges,
// and encryption hints for software components.
type cryptographyServer struct {
	pb.CryptographyServer
	db                      *sqlx.DB
	config                  *myconfig.ServerConfig
	algorithmHandler        *handlers.CryptographyAlgorithmHandler
	algorithmInRangeHandler *handlers.AlgorithmInRangeHandler
	versionsInRangeHandler  *handlers.VersionsInRangeHandler
	hintsInRangeHandler     *handlers.HintsRangeHandler
	encryptionHintsHandler  *handlers.EncryptionHintsHandler
}

// NewCryptographyServer creates a new instance of Cryptography Server.
func NewCryptographyServer(db *sqlx.DB, config *myconfig.ServerConfig) pb.CryptographyServer {
	// setupMetrics()
	return &cryptographyServer{db: db, config: config,
		algorithmHandler:        handlers.NewCryptographyAlgorithmHandler(db, config),
		algorithmInRangeHandler: handlers.NewAlgorithmInRangeHandler(db, config),
		versionsInRangeHandler:  handlers.NewVersionsInRangeHandler(db, config),
		hintsInRangeHandler:     handlers.NewHintsInRangeHandler(db, config),
		encryptionHintsHandler:  handlers.NewEncryptionHintsHandler(db, config),
	}
}

// Echo sends back the same message received.
func (c cryptographyServer) Echo(ctx context.Context, request *common.EchoRequest) (*common.EchoResponse, error) {
	s := ctxzap.Extract(ctx).Sugar()
	s.Infof("Received (%v): %v", ctx, request.GetMessage())
	return &common.EchoResponse{Message: request.GetMessage()}, nil
}

// *************************************** Algorithms handlers ***************************************/

// Deprecated: use GetComponentsAlgorithms instead.
func (c cryptographyServer) GetAlgorithms(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmResponse, error) {
	return c.algorithmHandler.GetAlgorithms(ctx, request)
}

// GetComponentsAlgorithms retrieves cryptographic algorithms for multiple components.
func (c cryptographyServer) GetComponentsAlgorithms(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsResponse, error) {
	return c.algorithmHandler.GetComponentsAlgorithms(ctx, request)
}

// GetComponentAlgorithms retrieves cryptographic algorithms for multiple components.
func (c cryptographyServer) GetComponentAlgorithms(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsResponse, error) {
	return c.algorithmHandler.GetComponentAlgorithms(ctx, request)
}

// *************************************** Algorithm in range handlers ***************************************/

// GetAlgorithmsInRange retrieves cryptographic algorithms within a version range for a single component.
func (c cryptographyServer) GetAlgorithmsInRange(ctx context.Context, request *common.PurlRequest) (*pb.AlgorithmsInRangeResponse, error) {
	return c.algorithmInRangeHandler.GetAlgorithmsInRange(ctx, request)
}

// GetComponentsAlgorithmsInRange retrieves cryptographic algorithms within version ranges for multiple components.
func (c cryptographyServer) GetComponentsAlgorithmsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsAlgorithmsInRangeResponse, error) {
	return c.algorithmInRangeHandler.GetComponentsAlgorithmsInRange(ctx, request)
}

// GetComponentAlgorithmsInRange retrieves cryptographic algorithms within a version range for a component.
func (c cryptographyServer) GetComponentAlgorithmsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentAlgorithmsInRangeResponse, error) {
	return c.algorithmInRangeHandler.GetComponentAlgorithmsInRange(ctx, request)
}

// *************************************** Versions in range handlers ***************************************/

// Deprecated: use GetComponentsVersionsInRange instead.
func (c cryptographyServer) GetVersionsInRange(ctx context.Context, request *common.PurlRequest) (*pb.VersionsInRangeResponse, error) {
	return c.versionsInRangeHandler.GetVersionsInRange(ctx, request)
}

// GetComponentsVersionsInRange retrieves versions within specified ranges for multiple components.
func (c cryptographyServer) GetComponentsVersionsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsVersionsInRangeResponse, error) {
	return c.versionsInRangeHandler.GetComponentsVersionsInRange(ctx, request)
}

// GetComponentVersionsInRange retrieves versions within a specified range for a component.
func (c cryptographyServer) GetComponentVersionsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentVersionsInRangeResponse, error) {
	return c.versionsInRangeHandler.GetComponentVersionsInRange(ctx, request)
}

// *************************************** Hints in range handlers ***************************************/

// Deprecated: use GetComponentsHintsInRange instead.
func (c cryptographyServer) GetHintsInRange(ctx context.Context, request *common.PurlRequest) (*pb.HintsInRangeResponse, error) {
	return c.hintsInRangeHandler.GetHintsInRange(ctx, request)
}

// GetComponentsHintsInRange retrieves cryptographic hints within version ranges for multiple components.
func (c cryptographyServer) GetComponentsHintsInRange(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsHintsInRangeResponse, error) {
	return c.hintsInRangeHandler.GetComponentsHintsInRange(ctx, request)
}

// GetComponentHintsInRange retrieves cryptographic hints within a version range for a component.
func (c cryptographyServer) GetComponentHintsInRange(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentHintsInRangeResponse, error) {
	return c.hintsInRangeHandler.GetComponentHintsInRange(ctx, request)
}

// *************************************** Encryption hints handlers ***************************************/

// Deprecated: use GetComponentsEncryptionHints instead.
func (c cryptographyServer) GetEncryptionHints(ctx context.Context, request *common.PurlRequest) (*pb.HintsResponse, error) {
	return c.encryptionHintsHandler.GetEncryptionHints(ctx, request)
}

// GetComponentsEncryptionHints retrieves encryption hints for multiple components.
func (c cryptographyServer) GetComponentsEncryptionHints(ctx context.Context, request *common.ComponentsRequest) (*pb.ComponentsEncryptionHintsResponse, error) {
	return c.encryptionHintsHandler.GetComponentsEncryptionHints(ctx, request)
}

// GetComponentEncryptionHints retrieves encryption hints for a single component.
func (c cryptographyServer) GetComponentEncryptionHints(ctx context.Context, request *common.ComponentRequest) (*pb.ComponentEncryptionHintsResponse, error) {
	return c.encryptionHintsHandler.GetComponentEncryptionHints(ctx, request)
}
