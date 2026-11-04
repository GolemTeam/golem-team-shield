package agentposture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI       string `json:"uri"`
			URIBaseID string `json:"uriBaseId,omitempty"`
		} `json:"artifactLocation"`
		Region *struct {
			StartLine int `json:"startLine"`
		} `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

func sarifLevel(severity string) string {
	switch severity {
	case Dangerous:
		return "error"
	case Suspicious:
		return "warning"
	}
	return "note"
}

// sarifURI places a finding's file. A repository's paths are relative to
// SRCROOT, for code scanning; a machine's are relative to HOME, whose value is
// left out so the report never carries a user name.
func sarifURI(res Result, loc string) (uri, base string, ok bool) {
	switch {
	case loc == "", strings.HasPrefix(loc, `HKCU\`), strings.HasPrefix(loc, `HKLM\`):
		return "", "", false
	case res.Repo != "":
		return filepath.ToSlash(loc), "SRCROOT", true
	case strings.HasPrefix(loc, "~/"), strings.HasPrefix(loc, `~\`):
		return filepath.ToSlash(loc[2:]), "HOME", true
	}
	p := filepath.ToSlash(loc)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p, "", true
}

// WriteSARIF writes a scan as SARIF 2.1.0, for GitHub code scanning and other
// tools that read it. Protections are not findings and are left out; the
// grade and area scores ride the run's properties.
func WriteSARIF(w io.Writer, res Result, version string) error {
	rep := Score(res)
	rules := map[string]bool{}
	var results []sarifResult
	for _, it := range res.Items {
		if it.Area == AreaProtections {
			continue
		}
		rules[it.Check] = true
		sum := sha256.Sum256([]byte(it.Client + "\x00" + it.Check + "\x00" + it.Location + "\x00" + it.Subject + "\x00" + it.Setting))
		r := sarifResult{
			RuleID: it.Check, Level: sarifLevel(it.Severity), Message: sarifText{summary(it)},
			PartialFingerprints: map[string]string{"golemCheck/v1": hex.EncodeToString(sum[:])},
			Properties:          map[string]any{"client": it.Client, "area": it.Area, "severity": it.Severity, "scope": it.Scope},
		}
		if uri, base, ok := sarifURI(res, it.Location); ok {
			var l sarifLocation
			l.PhysicalLocation.ArtifactLocation.URI = uri
			l.PhysicalLocation.ArtifactLocation.URIBaseID = base
			if it.Line > 0 {
				l.PhysicalLocation.Region = &struct {
					StartLine int `json:"startLine"`
				}{it.Line}
			}
			r.Locations = []sarifLocation{l}
		}
		results = append(results, r)
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	driver := sarifDriver{Name: "golem-check", Version: version,
		InformationURI: "https://github.com/GolemTeam/golem-team-shield", Rules: []sarifRule{}}
	for _, id := range ids {
		r := RuleFor(id)
		driver.Rules = append(driver.Rules, sarifRule{ID: id, Name: id, ShortDescription: sarifText{r.Title},
			Properties: map[string]any{"area": r.Area, "tags": []string{"security", r.Area}}})
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{{
		Tool: sarifTool{driver}, Results: results,
		Properties: map[string]any{"grade": rep.Grade, "score": rep.Score, "scoreVersion": rep.Version, "areas": rep.Areas},
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
