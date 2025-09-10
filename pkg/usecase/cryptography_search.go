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

package usecase

import (
	"context"
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/package-url/packageurl-go"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoUseCase struct {
	ctx         context.Context
	s           *zap.SugaredLogger
	conn        *sqlx.Conn
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}
type CryptoWorkerStruct struct {
	URLMd5  string
	Purl    string
	Version string
}
type InternalQuery struct {
	CompletePurl    string
	PurlName        string
	Requirement     string
	SelectedVersion string
	SelectedURLS    []models.AllURL
}

func NewCrypto(ctx context.Context, s *zap.SugaredLogger, conn *sqlx.Conn, config *myconfig.ServerConfig) *CryptoUseCase {
	return &CryptoUseCase{ctx: ctx, s: s, conn: conn,
		allUrls:     models.NewAllURLModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
		cryptoUsage: models.NewCryptoUsageModel(ctx, s, database.NewDBSelectContext(s, nil, conn, config.Database.Trace)),
	}
}

// GetComponentsAlgorithms takes a list of ComponentDTO objects, searches for cryptographic usages and returns a CryptoOutput struct.
func (d CryptoUseCase) GetComponentsAlgorithms(components []dtos.ComponentDTO) (dtos.CryptoOutput, models.QuerySummary, error) {
	if len(components) == 0 {
		d.s.Info("Empty List of Purls supplied")
		return dtos.CryptoOutput{}, models.QuerySummary{}, errors.New("empty list of purls")
	}
	query, purlsToQuery, mapPurls, summary := d.processInputPurls(components)

	// URLs by PurlList
	urls, err := d.allUrls.GetUrlsByPurlList(purlsToQuery)
	if err != nil {
		d.s.Warnf("Failed to get list of urls from (%v): %s", purlsToQuery, err)
	}
	urlSummary := d.processUrls(urls, mapPurls)
	summary.PurlsNotFound = append(summary.PurlsNotFound, urlSummary.PurlsNotFound...)
	if len(urls) == 0 {
		return dtos.CryptoOutput{}, summary, nil
	}

	purlMap := d.buildPurlMap(urls)
	urlHashes, err := d.collectURLHashes(query, purlMap)
	if err != nil {
		return dtos.CryptoOutput{}, models.QuerySummary{}, err
	}

	usage, err := d.cryptoUsage.GetCryptoUsageByURLHashes(urlHashes)
	if err != nil {
		return dtos.CryptoOutput{}, models.QuerySummary{}, errors.New("error retrieving url hashes")
	}

	mapCrypto := d.buildCryptoMap(usage)
	output, purlsWOInfo := d.processCryptoOutput(query, mapCrypto, mapPurls)

	summary.PurlsWOInfo = append(summary.PurlsWOInfo, purlsWOInfo...)

	return output, summary, nil
}

func (d CryptoUseCase) processUrls(urls []models.AllURL, mapPurls map[string]bool) models.QuerySummary {
	summary := models.QuerySummary{}
	for _, u := range urls {
		mapPurls[u.PurlName] = true
	}
	for k, v := range mapPurls {
		if !v {
			summary.PurlsNotFound = append(summary.PurlsNotFound, k)
		}
	}
	return summary
}

func (d CryptoUseCase) processPurlVersion(purl packageurl.PackageURL, requirement string) string {
	if len(requirement) > 0 && strings.HasPrefix(requirement, "file:") {
		d.s.Debugf("Removing 'local' requirement for purl: %v (req: %v)", purl, requirement)
		return ""
	}

	if len(purl.Version) == 0 && len(requirement) > 0 {
		ver := purlhelper.GetVersionFromReq(requirement)
		if len(ver) > 0 {
			return ver
		}
	}
	return purl.Version
}

func (d CryptoUseCase) processInputPurls(components []dtos.ComponentDTO) ([]InternalQuery, []utils.PurlReq, map[string]bool, models.QuerySummary) {
	var query []InternalQuery
	var purlsToQuery []utils.PurlReq
	mapPurls := make(map[string]bool)
	summary := models.QuerySummary{}
	summary.TotalPurls = len(components)
	for _, c := range components {
		purl, err := purlhelper.PurlFromString(c.Purl)
		if err != nil {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			continue
		}
		purlName, err := purlhelper.PurlNameFromString(c.Purl)
		if err != nil {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			continue
		}
		version := d.processPurlVersion(purl, c.Requirement)

		d.s.Debugf("Purl to query: %v, Name: %s, Version: %s", purl, purlName, version)
		purlsToQuery = append(purlsToQuery, utils.PurlReq{Purl: purlName, Version: version})
		mapPurls[purlName] = false
		query = append(query, InternalQuery{CompletePurl: c.Purl, SelectedVersion: version, Requirement: c.Requirement, PurlName: purlName})
	}
	return query, purlsToQuery, mapPurls, summary
}

func (d CryptoUseCase) buildPurlMap(urls []models.AllURL) map[string][]models.AllURL {
	purlMap := make(map[string][]models.AllURL)
	for _, url := range urls {
		purlMap[url.PurlName] = append(purlMap[url.PurlName], url)
	}
	return purlMap
}

func (d CryptoUseCase) collectURLHashes(query []InternalQuery, purlMap map[string][]models.AllURL) ([]string, error) {
	var urlHashes []string
	for i := range query {
		selectedURLs, err := models.PickClosestUrls(d.s, purlMap[query[i].PurlName], query[i].PurlName, "", query[i].Requirement)
		if err != nil {
			return nil, err
		}

		query[i].SelectedURLS = selectedURLs
		if len(selectedURLs) > 0 {
			query[i].SelectedVersion = selectedURLs[0].Version
			for _, url := range selectedURLs {
				urlHashes = append(urlHashes, url.URLHash)
			}
		}
	}
	return urlHashes, nil
}

func (d CryptoUseCase) buildCryptoMap(usage []models.CryptoUsage) map[string][]models.CryptoItem {
	mapCrypto := make(map[string][]models.CryptoItem)
	for _, v := range usage {
		mapCrypto[v.URLHash] = append(mapCrypto[v.URLHash], models.CryptoItem{
			Algorithm: v.Algorithm,
			Strength:  v.Strength,
		})
	}
	return mapCrypto
}

func (d CryptoUseCase) processCryptoOutput(query []InternalQuery, mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) (dtos.CryptoOutput, []string) {
	retV := dtos.CryptoOutput{}
	var purlsWOInfo []string

	for _, q := range query {
		item := d.buildCryptoOutputItem(q, mapCrypto, mapPurls)
		retV.Cryptography = append(retV.Cryptography, item)
	}

	for k, v := range mapPurls {
		if !v {
			purlsWOInfo = append(purlsWOInfo, k)
		}
	}

	return retV, purlsWOInfo
}

func (d CryptoUseCase) processAlgorithms(items []models.CryptoItem, cryptoOutItem *dtos.CryptoOutputItem, algorithms map[string]bool) {
	for _, item := range items {
		algKey := strings.ToLower(item.Algorithm)
		if !algorithms[algKey] {
			cryptoOutItem.Algorithms = append(cryptoOutItem.Algorithms, dtos.CryptoUsageItem{
				Algorithm: algKey,
				Strength:  item.Strength,
			})
			algorithms[algKey] = true
		}
	}
}

func (d CryptoUseCase) buildCryptoOutputItem(q InternalQuery, mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) dtos.CryptoOutputItem {
	cryptoOutItem := dtos.CryptoOutputItem{
		Version:     q.SelectedVersion,
		Requirement: q.Requirement,
		Purl:        q.CompletePurl,
	}

	algorithms := make(map[string]bool)
	foundInfo := false

	for _, url := range q.SelectedURLS {
		if items := mapCrypto[url.URLHash]; len(items) > 0 {
			d.processAlgorithms(items, &cryptoOutItem, algorithms)
			foundInfo = true
		}
	}
	mapPurls[q.PurlName] = foundInfo
	return cryptoOutItem
}
