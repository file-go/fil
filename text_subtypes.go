package main

import (
	"encoding/csv"
	"strconv"
	"strings"
)

func detectTextSubtype(b []byte) string {
	const maxScan = 32 * 1024
	end := len(b)
	if end > maxScan {
		end = maxScan
	}

	top := string(b[:end])
	topLower := strings.ToLower(top)
	topLower = "\n" + topLower

	if hasAll(topLower, "\nfrom:", "\nto:", "\nsubject:", "\ndate:") {
		return "email"
	}

	if looksLikeOpenVPN(topLower) {
		return "OpenVPN config"
	}

	if isINI, hasExtensions := looksLikeINI(top); isINI {
		if hasExtensions {
			return "Generic INItialization configuration [extensions]"
		}
		return "Generic INItialization configuration"
	}

	if strings.HasPrefix(top, "#!/bin/sh") || strings.HasPrefix(top, "#!/bin/bash") || strings.HasPrefix(top, "#!/usr/bin/env sh") {
		return "shell script"
	}

	if strings.HasPrefix(top, "#!/usr/bin/python") || strings.HasPrefix(top, "#!/usr/bin/env python") {
		return "Python script"
	}

	if looksLikePython(topLower) {
		return "Python script"
	}

	if strings.Contains(topLower, "\n#requires") || strings.Contains(topLower, "\nparam(") || strings.Contains(topLower, "\nparam\n(") || strings.Contains(topLower, "$psversiontable") {
		return "PowerShell script"
	}

	if looksLikePowerShell(topLower) {
		return "PowerShell script"
	}

	if strings.HasPrefix(topLower, "\n#!/usr/bin/perl") || strings.HasPrefix(topLower, "\n#!/usr/bin/env perl") {
		return "Perl script"
	}

	if looksLikePerl(topLower) {
		return "Perl script"
	}

	if looksLikeBatch(topLower) {
		return "Windows batch script"
	}

	if looksLikeTypeScript(topLower) {
		return "TypeScript"
	}

	if looksLikeJavaScript(topLower) {
		return "JavaScript"
	}

	if delimited := detectDelimitedSubtype(top); delimited != "" {
		return delimited
	}

	if looksLikeMarkdown(top) {
		return "Markdown text"
	}

	if looksLikeYAML(top) {
		return "YAML"
	}

	return ""
}

func hasAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func looksLikeOpenVPN(s string) bool {
	hits := 0
	if strings.Contains(s, "\nclient") {
		hits++
	}
	if strings.Contains(s, "\ndev ") {
		hits++
	}
	if strings.Contains(s, "\nproto ") {
		hits++
	}
	if strings.Contains(s, "\nremote ") {
		hits++
	}
	return hits >= 2
}

func looksLikeJavaScript(s string) bool {
	if looksLikePython(s) || looksLikePowerShell(s) || looksLikePerl(s) || looksLikeBatch(s) || looksLikeTypeScript(s) {
		return false
	}

	hits := 0
	if strings.Contains(s, "=>") {
		hits++
	}
	if strings.Contains(s, "\nlet ") {
		hits++
	}
	if strings.Contains(s, "function ") || strings.Contains(s, "\nfunction ") {
		hits++
	}
	if strings.Contains(s, "const ") || strings.Contains(s, "\nconst ") {
		hits++
	}
	if strings.Contains(s, "import ") || strings.Contains(s, "\nimport ") {
		hits++
	}
	if strings.Contains(s, "export ") || strings.Contains(s, "\nexport ") {
		hits++
	}
	return hits >= 2
}

func looksLikeTypeScript(s string) bool {
	if looksLikePython(s) || looksLikePowerShell(s) || looksLikePerl(s) || looksLikeBatch(s) {
		return false
	}

	hits := 0
	if strings.Contains(s, "\ninterface ") {
		hits++
	}
	if strings.Contains(s, "\ntype ") {
		hits++
	}
	if strings.Contains(s, "\nenum ") {
		hits++
	}
	if strings.Contains(s, "implements ") {
		hits++
	}
	if strings.Contains(s, ": string") || strings.Contains(s, ": number") || strings.Contains(s, ": boolean") {
		hits++
	}
	if strings.Contains(s, " as const") || strings.Contains(s, " as ") {
		hits++
	}
	return hits >= 2
}

func looksLikePython(s string) bool {
	hits := 0
	if strings.Contains(s, "\ndef ") {
		hits++
	}
	if strings.Contains(s, "\nclass ") {
		hits++
	}
	if strings.Contains(s, "\nfrom ") && strings.Contains(s, " import ") {
		hits++
	}
	if strings.Contains(s, "\nimport ") {
		hits++
	}
	if strings.Contains(s, "\nif __name__ == \"__main__\":") || strings.Contains(s, "\nif __name__ == '__main__':") {
		hits++
	}
	return hits >= 2
}

func looksLikePowerShell(s string) bool {
	hits := 0
	if strings.Contains(s, "\nfunction ") {
		hits++
	}
	if strings.Contains(s, "\nparam(") {
		hits++
	}
	if strings.Contains(s, "\n$") {
		hits++
	}
	if strings.Contains(s, "write-host") || strings.Contains(s, "write-output") {
		hits++
	}
	if strings.Contains(s, "get-") || strings.Contains(s, "set-") || strings.Contains(s, "new-") {
		hits++
	}
	return hits >= 2
}

func looksLikePerl(s string) bool {
	hits := 0
	if strings.Contains(s, "\nuse strict;") || strings.Contains(s, "\nuse warnings;") {
		hits++
	}
	if strings.Contains(s, "\nmy $") {
		hits++
	}
	if strings.Contains(s, "\nsub ") {
		hits++
	}
	if strings.Contains(s, "print $") || strings.Contains(s, "print \"") || strings.Contains(s, "print '") {
		hits++
	}
	if strings.Contains(s, "elsif ") || strings.Contains(s, "unless ") {
		hits++
	}
	return hits >= 2
}

func looksLikeBatch(s string) bool {
	hits := 0
	if strings.Contains(s, "\n@echo off") {
		hits++
	}
	if strings.Contains(s, "\nsetlocal") || strings.Contains(s, "\nendlocal") {
		hits++
	}
	if strings.Contains(s, "\nif exist ") || strings.Contains(s, "\nif not exist ") {
		hits++
	}
	if strings.Contains(s, "\ngoto ") || strings.Contains(s, "\ncall ") {
		hits++
	}
	if strings.Contains(s, "\n%") {
		hits++
	}
	if strings.Contains(s, "\nrem ") || strings.Contains(s, "\n::") {
		hits++
	}
	return hits >= 2
}

func looksLikeINI(s string) (bool, bool) {
	lines := strings.Split(s, "\n")
	sections := 0
	keyvals := 0
	hasExtensions := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end > 1 && isValidINISectionLine(line, end) {
				section := strings.TrimSpace(line[1:end])
				if !isLikelyINISectionName(section) {
					continue
				}
				sections++
				if strings.EqualFold(section, "extensions") {
					hasExtensions = true
				}
				continue
			}
		}

		eq := strings.Index(line, "=")
		if eq > 0 && eq < len(line)-1 {
			key := strings.TrimSpace(line[:eq])
			if isLikelyINIKeyName(key) {
				keyvals++
			}
		}
	}

	return sections > 0 && keyvals > 0, hasExtensions
}

func isValidINISectionLine(line string, closingBracket int) bool {
	rest := strings.TrimSpace(line[closingBracket+1:])
	return rest == "" || strings.HasPrefix(rest, ";") || strings.HasPrefix(rest, "#")
}

func isLikelyINISectionName(name string) bool {
	return isLikelyINIIdentifier(name)
}

func isLikelyINIKeyName(name string) bool {
	return isLikelyINIIdentifier(name)
}

func isLikelyINIIdentifier(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '_', '-', '.', ' ', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func looksLikeYAML(s string) bool {
	lines := strings.Split(s, "\n")
	keyValLines := 0
	startMarker := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "---" {
			startMarker = true
			continue
		}
		if strings.HasPrefix(line, "- ") {
			continue
		}

		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		// Ignore URLs and obvious non-YAML tokens that tend to be false positives.
		if strings.Contains(line, "://") || strings.Contains(line, "{") || strings.Contains(line, "}") || strings.Contains(line, ";") {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		if key == "" {
			continue
		}
		keyValLines++
	}

	if startMarker && keyValLines >= 1 {
		return true
	}
	return keyValLines >= 2
}

func detectDelimitedSubtype(s string) string {
	csvScore := scoreDelimited(s, ',')
	tsvScore := scoreDelimited(s, '\t')
	const minScore = 1.2

	if csvScore < minScore && tsvScore < minScore {
		return ""
	}
	if tsvScore > csvScore+0.15 {
		return "TSV text"
	}
	if csvScore > tsvScore+0.15 {
		return "CSV text"
	}
	if tsvScore > csvScore {
		return "TSV text"
	}
	return "CSV text"
}

func scoreDelimited(s string, delim rune) float64 {
	lines := strings.Split(s, "\n")
	validRows := make([][]string, 0, 64)
	fieldCountHits := make(map[int]int)
	delimiterLines := 0
	maxLines := 60

	for _, line := range lines {
		if len(validRows) >= maxLines {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.ContainsRune(line, delim) {
			continue
		}
		delimiterLines++

		r := csv.NewReader(strings.NewReader(line))
		r.Comma = delim
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		r.TrimLeadingSpace = true
		fields, err := r.Read()
		if err != nil {
			continue
		}
		fields = trimTrailingEmptyFields(fields)
		if len(fields) < 3 {
			continue
		}

		validRows = append(validRows, fields)
		fieldCountHits[len(fields)]++
	}

	valid := len(validRows)
	if valid < 4 || delimiterLines < 4 {
		return 0
	}

	modeFields := 0
	modeCount := 0
	for fieldCount, count := range fieldCountHits {
		if count > modeCount {
			modeCount = count
			modeFields = fieldCount
		}
	}

	if modeFields < 2 {
		return 0
	}

	nearModeCount := 0
	for fieldCount, count := range fieldCountHits {
		if fieldCount >= modeFields-1 && fieldCount <= modeFields+1 {
			nearModeCount += count
		}
	}

	consistency := float64(nearModeCount) / float64(valid)
	if consistency < 0.85 {
		return 0
	}

	// Header-like boost: first structured row text-heavy + subsequent row numeric-heavy.
	var header []string
	var second []string
	for _, row := range validRows {
		if len(row) != modeFields {
			continue
		}
		if header == nil {
			header = row
			continue
		}
		second = row
		break
	}

	score := consistency*2.0 + float64(valid)/20.0
	if header != nil && second != nil && isMostlyTextRow(header) && isMostlyNumericRow(second) {
		score += 0.35
	}
	return score
}

func trimTrailingEmptyFields(fields []string) []string {
	end := len(fields)
	for end > 0 {
		if strings.TrimSpace(fields[end-1]) != "" {
			break
		}
		end--
	}
	return fields[:end]
}

func isMostlyTextRow(fields []string) bool {
	texty := 0
	nonEmpty := 0
	for _, field := range fields {
		f := strings.TrimSpace(field)
		if f == "" {
			continue
		}
		nonEmpty++
		if hasLetter(f) && !isNumericField(f) {
			texty++
		}
	}
	return nonEmpty > 0 && texty*2 >= nonEmpty
}

func isMostlyNumericRow(fields []string) bool {
	numeric := 0
	nonEmpty := 0
	for _, field := range fields {
		f := strings.TrimSpace(field)
		if f == "" {
			continue
		}
		nonEmpty++
		if isNumericField(f) {
			numeric++
		}
	}
	return nonEmpty > 0 && numeric*2 >= nonEmpty
}

func isNumericField(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	s = strings.TrimPrefix(s, "$")
	if strings.HasSuffix(s, "%") {
		s = strings.TrimSuffix(s, "%")
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func looksLikeMarkdown(s string) bool {
	lines := strings.Split(s, "\n")
	const maxLines = 200
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}

	typeMask := 0
	score := 0
	nonEmpty := 0

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		nonEmpty++

		// ATX headings: #, ##, ### ...
		if isMarkdownHeading(line) {
			score += 3
			typeMask |= 1 << 0
			continue
		}

		// Setext headings: text followed by ==== or ----
		if i+1 < len(lines) && isSetextUnderline(strings.TrimSpace(lines[i+1])) && !strings.HasPrefix(line, "#") {
			score += 3
			typeMask |= 1 << 1
			continue
		}

		// Fenced code block markers.
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			score += 3
			typeMask |= 1 << 2
		}

		// List markers.
		if isMarkdownListItem(line) {
			score++
			typeMask |= 1 << 3
		}

		// Blockquote marker.
		if strings.HasPrefix(line, "> ") || strings.HasPrefix(line, ">\t") {
			score++
			typeMask |= 1 << 4
		}

		// Links / reference links.
		if hasMarkdownLink(line) {
			score += 2
			typeMask |= 1 << 5
		}

		// Inline markdown emphasis / code.
		if hasMarkdownInlineMarkup(line) {
			score++
			typeMask |= 1 << 6
		}
	}

	if nonEmpty < 3 {
		return false
	}

	kinds := bitCount(typeMask)
	if kinds < 2 {
		return false
	}

	// Keep this conservative to avoid classifying plain prose as markdown.
	return score >= 5
}

func isMarkdownHeading(line string) bool {
	if len(line) < 2 || line[0] != '#' {
		return false
	}
	i := 0
	for i < len(line) && line[i] == '#' {
		i++
	}
	return i >= 1 && i <= 6 && i < len(line) && line[i] == ' '
}

func isSetextUnderline(line string) bool {
	if len(line) < 3 {
		return false
	}
	allEq := true
	allDash := true
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '=':
			allDash = false
		case '-':
			allEq = false
		default:
			return false
		}
	}
	return allEq || allDash
}

func isMarkdownListItem(line string) bool {
	if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "+ ") {
		return true
	}
	j := 0
	for j < len(line) && line[j] >= '0' && line[j] <= '9' {
		j++
	}
	return j > 0 && j+1 < len(line) && line[j] == '.' && line[j+1] == ' '
}

func hasMarkdownLink(line string) bool {
	if strings.Contains(line, "][") && strings.Contains(line, "]:") {
		return true
	}
	lb := strings.Index(line, "[")
	if lb < 0 {
		return false
	}
	rb := strings.Index(line[lb+1:], "]")
	if rb < 0 {
		return false
	}
	rest := line[lb+1+rb+1:]
	return strings.HasPrefix(rest, "(") && strings.Contains(rest, ")")
}

func hasMarkdownInlineMarkup(line string) bool {
	if strings.Count(line, "`") >= 2 {
		return true
	}
	if strings.Count(line, "**") >= 1 || strings.Count(line, "__") >= 1 {
		return true
	}
	return strings.Count(line, "*") >= 2 || strings.Count(line, "_") >= 2
}

func bitCount(v int) int {
	count := 0
	for v != 0 {
		v &= v - 1
		count++
	}
	return count
}
