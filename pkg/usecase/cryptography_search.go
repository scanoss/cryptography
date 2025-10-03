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
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/package-url/packageurl-go"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"go.uber.org/zap"
	myconfig "scanoss.com/cryptography/pkg/config"
	"scanoss.com/cryptography/pkg/dtos"
	"scanoss.com/cryptography/pkg/models"
	"scanoss.com/cryptography/pkg/utils"
)

type CryptoUseCase struct {
	allUrls     *models.AllUrlsModel
	cryptoUsage *models.CryptoUsageModel
}
type CryptoWorkerStruct struct {
	URLMd5  string
	Purl    string
	Version string
}
type ComponentCryptoMetadata struct {
	Purl          string
	ComponentName string
	Requirement   string
	Version       string
	Status        dtos.Status
	SelectedURLS  []models.AllURL
}

func NewCrypto(db *sqlx.DB, config *myconfig.ServerConfig) *CryptoUseCase {
	return &CryptoUseCase{
		allUrls:     models.NewAllURLModel(db),
		cryptoUsage: models.NewCryptoUsageModel(db),
	}
}

// GetComponentsAlgorithms takes a list of ComponentDTO objects, searches for cryptographic usages and returns a CryptoOutput struct.
func (d CryptoUseCase) GetComponentsAlgorithms(ctx context.Context, s *zap.SugaredLogger, components []dtos.ComponentDTO) (dtos.CryptoOutput, error) {
	if len(components) == 0 {
		s.Info("Empty List of Purls supplied")
		return dtos.CryptoOutput{}, errors.New("empty list of purls")
	}
	componentCryptoMetadata, mapPurls, _ := d.processInputPurls(s, components)
	s.Debugf("Component Cryptography Metadata: %v", componentCryptoMetadata)
	// Only query with SUCCESS status components
	var successPurlsToQuery []utils.PurlReq
	for _, cm := range componentCryptoMetadata {
		if cm.Status == dtos.StatusSuccess {
			successPurlsToQuery = append(successPurlsToQuery, utils.PurlReq{
				Purl:    cm.ComponentName,
				Version: cm.Version,
			})
		}
	}

	// URLs by PurlList (only SUCCESS components)
	var urls []models.AllURL
	var err error
	if len(successPurlsToQuery) > 0 {
		urls, err = d.allUrls.GetUrlsByPurlList(ctx, s, successPurlsToQuery)
		if err != nil {
			s.Warnf("Failed to get list of urls from (%v): %s", successPurlsToQuery, err)
		}
		d.processUrls(urls, componentCryptoMetadata)
	}

	// summary.PurlsNotFound = append(summary.PurlsNotFound, urlSummary.PurlsNotFound...)

	purlMap := d.buildPurlMap(urls)
	urlHashes, err := d.collectURLHashes(s, componentCryptoMetadata, purlMap)
	if err != nil {
		return dtos.CryptoOutput{}, err
	}
	var usage []models.CryptoUsage
	if len(urlHashes) > 0 {
		usage, err = d.cryptoUsage.GetCryptoUsageByURLHashes(ctx, s, urlHashes)
		if err != nil {
			return dtos.CryptoOutput{}, errors.New("error retrieving url hashes")
		}
	}

	mapCrypto := d.buildCryptoMap(usage)
	output := d.processCryptoOutput(componentCryptoMetadata, mapCrypto, mapPurls)

	return output, nil
}

func (d CryptoUseCase) processUrls(urls []models.AllURL, componentCryptoMetadata []ComponentCryptoMetadata) {
	// Build a map from PurlName to list of URLs for easy lookup
	urlsByPurl := make(map[string][]models.AllURL)
	for _, u := range urls {
		urlsByPurl[u.PurlName] = append(urlsByPurl[u.PurlName], u)
	}
	// Update component metadata with matched URLs
	for i := range componentCryptoMetadata {
		if componentCryptoMetadata[i].Status == dtos.StatusSuccess {
			if matchedUrls, found := urlsByPurl[componentCryptoMetadata[i].ComponentName]; found {
				componentCryptoMetadata[i].SelectedURLS = matchedUrls
			} else {
				componentCryptoMetadata[i].Status = dtos.ComponentNotFound
			}
		}
	}
}

func (d CryptoUseCase) processPurlVersion(s *zap.SugaredLogger, purl packageurl.PackageURL, requirement string) string {
	if len(requirement) > 0 && strings.HasPrefix(requirement, "file:") {
		s.Debugf("Removing 'local' requirement for purl: %v (req: %v)", purl, requirement)
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

func (d CryptoUseCase) processInputPurls(s *zap.SugaredLogger, components []dtos.ComponentDTO) ([]ComponentCryptoMetadata, map[string]bool, models.QuerySummary) {
	var componentCryptoMetadata []ComponentCryptoMetadata
	mapPurls := make(map[string]bool)
	summary := models.QuerySummary{}
	summary.TotalPurls = len(components)
	for i := range components {
		c := &components[i]
		purl, err := purlhelper.PurlFromString(c.Purl)
		if err != nil {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			componentCryptoMetadata = append(componentCryptoMetadata, ComponentCryptoMetadata{Purl: c.Purl, Status: dtos.ComponentMalformed, ComponentName: "", Requirement: c.Requirement, Version: c.Version})
			continue
		}
		purlName, err := purlhelper.PurlNameFromString(c.Purl)
		if err != nil {
			summary.PurlsFailedToParse = append(summary.PurlsFailedToParse, c.Purl)
			componentCryptoMetadata = append(componentCryptoMetadata, ComponentCryptoMetadata{Purl: c.Purl, Status: dtos.ComponentMalformed, ComponentName: "", Requirement: c.Requirement, Version: c.Version})
			continue
		}
		version := d.processPurlVersion(s, purl, c.Requirement)
		s.Debugf("Purl to query: %v, Name: %s, Version: %s", purl, purlName, version)
		mapPurls[purlName] = false
		componentCryptoMetadata = append(componentCryptoMetadata, ComponentCryptoMetadata{Purl: c.Purl, Version: version, Status: dtos.StatusSuccess, Requirement: c.Requirement, ComponentName: purlName})
	}
	fmt.Printf("COMPONENT METADATA: %v", componentCryptoMetadata)
	return componentCryptoMetadata, mapPurls, summary
}

func (d CryptoUseCase) buildPurlMap(urls []models.AllURL) map[string][]models.AllURL {
	purlMap := make(map[string][]models.AllURL)
	for _, url := range urls {
		purlMap[url.PurlName] = append(purlMap[url.PurlName], url)
	}
	return purlMap
}

func (d CryptoUseCase) collectURLHashes(s *zap.SugaredLogger, componentCryptoMetadata []ComponentCryptoMetadata, purlMap map[string][]models.AllURL) ([]string, error) {
	var urlHashes []string
	for i := range componentCryptoMetadata {
		// Skip malformed components
		if componentCryptoMetadata[i].Status != dtos.StatusSuccess {
			continue
		}

		urls := componentCryptoMetadata[i].SelectedURLS
		selectedURLs, err := models.PickClosestUrls(s, urls, componentCryptoMetadata[i].ComponentName, "", componentCryptoMetadata[i].Requirement)
		if err != nil {
			return nil, err
		}
		componentCryptoMetadata[i].SelectedURLS = selectedURLs
		if len(selectedURLs) > 0 {
			componentCryptoMetadata[i].Version = selectedURLs[0].Version
			for _, url := range selectedURLs {
				urlHashes = append(urlHashes, url.URLHash)
			}
		} else {

			// No URLs found for this component
			if componentCryptoMetadata[i].Status != dtos.ComponentMalformed {
				componentCryptoMetadata[i].Status = dtos.ComponentNotFound
			}
			componentCryptoMetadata[i].SelectedURLS = []models.AllURL{}
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

func (d CryptoUseCase) processCryptoOutput(componentCryptoMetadata []ComponentCryptoMetadata, mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) dtos.CryptoOutput {
	output := dtos.CryptoOutput{}

	for _, c := range componentCryptoMetadata {
		item := d.buildCryptoOutputItem(c, mapCrypto, mapPurls)
		output.Cryptography = append(output.Cryptography, item)
	}
	return output
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

func (d CryptoUseCase) buildCryptoOutputItem(q ComponentCryptoMetadata, mapCrypto map[string][]models.CryptoItem, mapPurls map[string]bool) dtos.CryptoOutputItem {
	cryptoOutItem := dtos.CryptoOutputItem{
		Version:     q.Version,
		Requirement: q.Requirement,
		Purl:        q.Purl,
		Status:      q.Status,
	}

	if q.Status == dtos.StatusSuccess {
		algorithms := make(map[string]bool)
		foundInfo := false

		for _, url := range q.SelectedURLS {
			if items := mapCrypto[url.URLHash]; len(items) > 0 {
				d.processAlgorithms(items, &cryptoOutItem, algorithms)
				foundInfo = true
			}
		}

		// Update status based on whether we found crypto info
		if !foundInfo {
			cryptoOutItem.Status = dtos.ComponentWithoutInfo
		}
		mapPurls[q.ComponentName] = foundInfo
	}

	return cryptoOutItem
}
