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

package models

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"

	"github.com/Masterminds/semver/v3"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"

	"scanoss.com/cryptography/pkg/utils"
)

type AllUrlsModel struct {
	ctx context.Context
	s   *zap.SugaredLogger
	q   *database.DBQueryContext
}

type AllURL struct {
	URLHash   string `db:"url_hash"`
	Component string `db:"component"`
	Version   string `db:"version"`
	SemVer    string `db:"semver"`
	PurlName  string `db:"purl_name"`
	PurlType  string `db:"purl_type"` // TODO remove?
	MineID    int32  `db:"mine_id"`
	URL       string `db:"-"` // TODO remove?
}

// NewAllURLModel creates a new instance of the All URL Model.
func NewAllURLModel(ctx context.Context, s *zap.SugaredLogger, q *database.DBQueryContext) *AllUrlsModel {
	return &AllUrlsModel{ctx: ctx, s: s, q: q}
}

func (m *AllUrlsModel) GetUrlsByPurlList(list []utils.PurlReq) ([]AllURL, error) {
	if len(list) == 0 {
		m.s.Infof("Please specify a valid Purl list to query")
		return []AllURL{}, errors.New("please specify a valid Purl list to query")
	}
	var purlNames []string
	for p := range list {
		purlNames = append(purlNames, "'"+list[p].Purl+"'")
	}
	inStmt := strings.Join(purlNames, ",")
	inStmt = "(" + inStmt + ")"
	stmt := "SELECT package_hash AS url_hash, component, v.version_name AS version, v.semver AS semver, m.purl_type as purl_type, " +
		"purl_name, mine_id FROM all_urls u " +
		"LEFT JOIN mines m ON u.mine_id = m.id " +
		"LEFT JOIN versions v ON u.version_id = v.id " +
		"WHERE u.purl_name in " + inStmt +
		" and package_hash!= '' ORDER BY date DESC;"

	var allUrls []AllURL
	err := m.q.SelectContext(m.ctx, &allUrls, stmt)
	if err != nil {
		m.s.Errorf("Failed to query a list of urls:  %v", err)
		return []AllURL{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	return allUrls, nil
}

// GetUrlsByPurlString searches for component details of the specified Purl string (and optional requirement).
func (m *AllUrlsModel) GetUrlsByPurlString(purlString, purlReq string) (AllURL, error) {
	// TODO remove?
	if len(purlString) == 0 {
		m.s.Errorf("Please specify a valid Purl String to query")
		return AllURL{}, errors.New("please specify a valid Purl String to query")
	}
	purl, err := purlhelper.PurlFromString(purlString)
	if err != nil {
		return AllURL{}, err
	}
	purlName, err := purlhelper.PurlNameFromString(purlString) // Make sure we just have the bare minimum for a Purl Name
	if err != nil {
		return AllURL{}, err
	}
	if len(purlReq) > 0 && strings.HasPrefix(purlReq, "file:") { // internal dependency requirement. Assume latest
		m.s.Debugf("Removing 'local' requirement for purl: %v (req: %v)", purlString, purlReq)
		purlReq = ""
	}
	if len(purl.Version) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
		ver := purlhelper.GetVersionFromReq(purlReq)
		if len(ver) > 0 {
			purl.Version = ver // Switch to exact version search (faster)
			purlReq = ""
		}
	}

	if len(purl.Version) > 0 {
		return m.GetUrlsByPurlNameTypeVersion(purlName, purl.Type, purl.Version)
	}
	return m.GetUrlsByPurlNameType(purlName, purl.Type, purlReq)
}

// GetUrlsByPurlNameType searches for component details of the specified Purl Name/Type (and optional requirement).
func (m *AllUrlsModel) GetUrlsByPurlNameType(purlName, purlType, purlReq string) (AllURL, error) {
	// TODO remove?
	if len(purlName) == 0 {
		m.s.Errorf("Please specify a valid Purl Name to query")
		return AllURL{}, errors.New("please specify a valid Purl Name to query")
	}
	if len(purlType) == 0 {
		m.s.Errorf("Please specify a valid Purl Type to query: %v", purlName)
		return AllURL{}, errors.New("please specify a valid Purl Type to query")
	}
	var allUrls []AllURL
	err := m.q.SelectContext(m.ctx, &allUrls,
		"SELECT package_hash AS url_hash, component, v.version_name AS version, v.semver AS semver, "+
			"purl_name, mine_id FROM all_urls u "+
			"LEFT JOIN mines m ON u.mine_id = m.id "+
			"LEFT JOIN versions v ON u.version_id = v.id "+
			"WHERE m.purl_type = $1 AND u.purl_name = $2  "+
			"ORDER BY date DESC;",
		purlType, purlName)

	if err != nil {
		m.s.Errorf("Failed to query all urls table for %v - %v: %v", purlType, purlName, err)
		return AllURL{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	m.s.Debugf("Found %v results for %v, %v.", len(allUrls), purlType, purlName)
	// Pick one URL to return (checking for license details also)
	return pickOneURL(m.s, allUrls, purlName, purlType, purlReq)
}

// GetUrlsByPurlNameTypeVersion searches for component details of the specified Purl Name/Type and version.
func (m *AllUrlsModel) GetUrlsByPurlNameTypeVersion(purlName, purlType, purlVersion string) (AllURL, error) {
	// TODO remove?
	if len(purlName) == 0 {
		m.s.Errorf("Please specify a valid Purl Name to query")
		return AllURL{}, errors.New("please specify a valid Purl Name to query")
	}
	if len(purlType) == 0 {
		m.s.Errorf("Please specify a valid Purl Type to query")
		return AllURL{}, errors.New("please specify a valid Purl Type to query")
	}
	if len(purlVersion) == 0 {
		m.s.Errorf("Please specify a valid Purl Version to query")
		return AllURL{}, errors.New("please specify a valid Purl Version to query")
	}
	var allUrls []AllURL
	err := m.q.SelectContext(m.ctx, &allUrls,
		"SELECT package_hash AS url_hash, component, v.version_name AS version, v.semver AS semver, "+
			"purl_name, mine_id FROM all_urls u "+
			"LEFT JOIN mines m ON u.mine_id = m.id "+
			"LEFT JOIN versions v ON u.version_id = v.id "+
			"WHERE m.purl_type = $1 AND u.purl_name = $2 AND v.version_name = $3 AND is_mined = true "+
			"ORDER BY date DESC;",
		purlType, purlName, purlVersion)
	if err != nil {
		m.s.Errorf("Failed to query all urls table for %v - %v: %v", purlType, purlName, err)
		return AllURL{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	m.s.Debugf("Found %v results for %v, %v.", len(allUrls), purlType, purlName)
	// Pick one URL to return (checking for license details also)
	return pickOneURL(m.s, allUrls, purlName, purlType, "")
}

func (m *AllUrlsModel) GetUrlsByPurlNameTypeInRange(purlName, purlType, purlRange string) ([]AllURL, error) {
	// TODO remove?
	if len(purlName) == 0 {
		m.s.Infof("Please specify a valid Purl Name to query")
		return []AllURL{}, errors.New("please specify a valid Purl Name to query")
	}
	if len(purlType) == 0 {
		m.s.Infof("Please specify a valid Purl Type to query")
		return []AllURL{}, errors.New("please specify a valid Purl Type to query")
	}
	if len(purlRange) == 0 {
		m.s.Infof("Please specify a valid Purl Version range to query")
		return []AllURL{}, errors.New("please specify a valid Purl Version to query")
	}
	var allUrls []AllURL
	var filteredUrls []AllURL
	err := m.q.SelectContext(m.ctx, &allUrls,
		"SELECT package_hash AS url_hash, component, v.version_name AS version, v.semver AS semver, "+
			"purl_name, mine_id FROM all_urls u "+
			"LEFT JOIN mines m ON u.mine_id = m.id "+
			"LEFT JOIN versions v ON u.version_id = v.id "+
			"WHERE m.purl_type = $1 AND u.purl_name = $2 "+
			"AND package_hash!='404' "+
			"ORDER BY date DESC;",
		purlType, purlName)
	if err != nil {
		m.s.Infof("Failed to query all urls table for %v - %v: %v", purlType, purlName, err)
		return []AllURL{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	rangeSpec, err := semver.NewConstraint(purlRange)
	if err != nil {
		return []AllURL{}, fmt.Errorf("failed to analyze range: %v", err)
	}

	for _, u := range allUrls {
		// Analyze version
		version, err := semver.NewVersion(u.SemVer)
		if err != nil {
			continue
		}
		// Check if version is inside the range
		if rangeSpec.Check(version) {
			filteredUrls = append(filteredUrls, u)
		}
	}
	m.s.Debugf("Found %v results for %v, %v.", len(allUrls), purlType, purlName)
	// Pick one URL to return
	return filteredUrls, nil
}

// pickOneURL takes the potential matching component/versions and selects the most appropriate one
// obsolete in this application.
func pickOneURL(s *zap.SugaredLogger, allUrls []AllURL, purlName, purlType, purlReq string) (AllURL, error) {
	if len(allUrls) == 0 {
		s.Infof("No component match (in urls) found for %v, %v", purlName, purlType)
		return AllURL{}, nil
	}
	s.Debugf("Potential Matches: %v", allUrls)
	var c *semver.Constraints
	var urlMap = make(map[*semver.Version]AllURL)

	if len(purlReq) > 0 {
		s.Debugf("Building version constraint for %v: %v", purlName, purlReq)
		var err error
		c, err = semver.NewConstraint(purlReq)
		if err != nil {
			s.Warnf("Encountered an issue parsing version constraint string '%v' (%v,%v): %v", purlReq, purlName, purlType, err)
		}
	}

	s.Debugf("Checking versions...")
	for _, url := range allUrls {
		if len(url.SemVer) > 0 || len(url.Version) > 0 {
			v, err := semver.NewVersion(url.Version)
			if err != nil && len(url.SemVer) > 0 {
				s.Debugf("Failed to parse SemVer: '%v'. Trying Version instead: %v (%v)", url.Version, url.SemVer, err)
				v, err = semver.NewVersion(url.SemVer) // Semver failed, try the normal version
			}
			if err != nil {
				s.Warnf("Encountered an issue parsing version string '%v' (%v) for %v: %v. Using v0.0.0", url.Version, url.SemVer, url, err)
				v, err = semver.NewVersion("v0.0.0") // Semver failed, just use a standard version zero (for now)
			}
			if err == nil {
				if c == nil || c.Check(v) {
					_, ok := urlMap[v]
					if !ok {
						urlMap[v] = url // fits inside the constraint and hasn't already been stored
					}
				}
			}
		} else {
			s.Warnf("Skipping match as it doesn't have a version: %#v", url)
		}
	}
	if len(urlMap) == 0 { // TODO should we return the latest version anyway?
		s.Warnf("No component match found for %v, %v after filter %v", purlName, purlType, purlReq)
		return AllURL{}, nil
	}
	var versions = make([]*semver.Version, len(urlMap))
	var vi = 0
	for version := range urlMap { // Save the list of versions so they can be sorted
		versions[vi] = version
		vi++
	}
	s.Debugf("Version List: %v", versions)
	sort.Sort(semver.Collection(versions))
	version := versions[len(versions)-1] // Get the latest (acceptable) URL version
	s.Debugf("Sorted versions: %v. Highest: %v", versions, version)

	url, ok := urlMap[version] // Retrieve the latest accepted URL version
	if !ok {
		s.Errorf("Problem retrieving URL data for %v (%v, %v)", version, purlName, purlType)
		return AllURL{}, fmt.Errorf("failed to retrieve specific URL version: %v", version)
	}
	url.URL, _ = purlhelper.ProjectUrl(purlName, purlType)

	s.Debugf("Selected version: %#v", url)
	return url, nil // Return the best component match
}

// PickClosestUrls nolint: gocognit.
func PickClosestUrls(s *zap.SugaredLogger, allUrls []AllURL, purlName, purlType, purlReq string) ([]AllURL, error) {
	if len(allUrls) == 0 {
		s.Infof("No component match (in urls) found for %v, %v", purlName, purlType)
		return []AllURL{}, nil
	}
	var c *semver.Constraints
	var urlMap = make(map[*semver.Version][]AllURL)

	if len(purlReq) > 0 {
		s.Debugf("Building version constraint for %v: %v", purlName, purlReq)
		var err error
		c, err = semver.NewConstraint(purlReq)
		if err != nil {
			s.Warnf("Encountered an issue parsing version constraint string '%v' (%v,%v): %v", purlReq, purlName, purlType, err)
		}
	}
	s.Debugf("Checking versions...")
	for _, url := range allUrls {
		if len(url.SemVer) > 0 || len(url.Version) > 0 {
			v, err := semver.NewVersion(url.Version)
			if err != nil && len(url.SemVer) > 0 {
				s.Debugf("Failed to parse SemVer: '%v'. Trying Version instead: %v (%v)", url.Version, url.SemVer, err)
				v, err = semver.NewVersion(url.SemVer) // Semver failed, try the normal version
			}
			if err != nil {
				s.Warnf("Encountered an issue parsing version string '%v' (%v) for %v: %v. Using v0.0.0", url.Version, url.SemVer, url, err)
				v, err = semver.NewVersion("v0.0.0") // Semver failed, just use a standard version zero (for now)
			}
			if err == nil {
				if c == nil || c.Check(v) {
					found := false
					for k := range urlMap {
						if k.Equal(v) {
							urlMap[k] = append(urlMap[k], url)
							found = true
							break
						}
					}
					if !found {
						urlMap[v] = append(urlMap[v], url)
					}
				}
			}
		} else {
			s.Warnf("Skipping match as it doesn't have a version: %#v", url)
		}
	}
	if len(urlMap) == 0 { // TODO should we return the latest version anyway?
		s.Warnf("No component match found for %v, %v after filter %v", purlName, purlType, purlReq)
		return []AllURL{}, nil
	}
	var versions = make([]*semver.Version, len(urlMap))
	var vi = 0
	for version := range urlMap { // Save the list of versions so they can be sorted
		versions[vi] = version
		vi++
	}
	sort.Sort(semver.Collection(versions))
	version := versions[len(versions)-1] // Get the latest (acceptable) URL version

	url, ok := urlMap[version] // Retrieve the latest accepted URL version
	if !ok {
		s.Errorf("Problem retrieving URL data for %v (%v, %v)", version, purlName, purlType)
		return []AllURL{}, fmt.Errorf("failed to retrieve specific URL version: %v", version)
	}

	s.Debugf("Selected version: %#v", url)
	return url, nil // Return the closest URLs
}
