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

	if looksLikeEMLX(top) {
		return "Apple Mail message (emlx)"
	}

	if looksLikeMbox(top) {
		return "Mbox mailbox"
	}

	if hasAll(topLower, "\nfrom:", "\nto:", "\nsubject:", "\ndate:") {
		return "email"
	}

	if looksLikeOpenSSHPublicKey(top) {
		return "OpenSSH public key"
	}
	if looksLikeKnownHosts(top) {
		return "OpenSSH known_hosts"
	}
	if looksLikeAuthorizedKeys(top) {
		return "OpenSSH authorized_keys"
	}

	if looksLikeOpenVPN(topLower) {
		return "OpenVPN config"
	}

	if looksLikeDockerfile(top, topLower) {
		return "Dockerfile"
	}

	if strings.HasPrefix(top, "#!/bin/sh") || strings.HasPrefix(top, "#!/bin/bash") ||
		strings.HasPrefix(top, "#!/usr/bin/env sh") || strings.HasPrefix(top, "#!/usr/bin/env bash") ||
		strings.HasPrefix(top, "#!/usr/bin/zsh") || strings.HasPrefix(top, "#!/usr/bin/env zsh") ||
		strings.HasPrefix(top, "#!/usr/bin/fish") || strings.HasPrefix(top, "#!/usr/bin/env fish") {
		return "shell script"
	}

	if strings.HasPrefix(top, "#!/usr/bin/python") || strings.HasPrefix(top, "#!/usr/bin/env python") {
		return "Python script"
	}

	if strings.HasPrefix(top, "#!/usr/bin/env node") || strings.HasPrefix(top, "#!/usr/bin/node") ||
		strings.HasPrefix(top, "#!/usr/local/bin/node") {
		return "Node.js script"
	}

	if strings.HasPrefix(top, "#!/usr/bin/ruby") || strings.HasPrefix(top, "#!/usr/bin/env ruby") {
		return "Ruby script"
	}

	if looksLikeQML(topLower) {
		return "QML source"
	}

	if looksLikeRuby(topLower) {
		return "Ruby script"
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

	if looksLikePHP(topLower) {
		return "PHP script"
	}

	if looksLikeASPX(topLower) {
		return "ASP.NET page"
	}

	if looksLikeClassicASP(topLower) {
		return "ASP script"
	}

	if looksLikeJSP(topLower) {
		return "JSP page"
	}

	if looksLikeIISWebConfig(topLower) {
		return "IIS web.config"
	}

	if looksLikeApacheConfig(topLower) {
		return "Apache config"
	}

	if looksLikeNginxConfig(topLower) {
		return "Nginx config"
	}

	if looksLikeGo(top) {
		return "Go source"
	}

	if looksLikeRust(topLower) {
		return "Rust source"
	}

	if looksLikeJava(top, topLower) {
		return "Java source"
	}

	if cLike := looksLikeCLang(top, topLower); cLike != "" {
		return cLike
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

	if looksLikeTOML(top) {
		return "TOML configuration"
	}

	if looksLikeMakefile(top) {
		return "Makefile"
	}

	if isINI, hasExtensions := looksLikeINI(top); isINI {
		if hasExtensions {
			return "Generic INItialization configuration [extensions]"
		}
		return "Generic INItialization configuration"
	}

	if delimited := detectDelimitedSubtype(top); delimited != "" {
		return delimited
	}

	if looksLikeYAML(top) {
		return "YAML"
	}

	if looksLikeMarkdown(top) {
		return "Markdown text"
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

func looksLikeOpenSSHPublicKey(s string) bool {
	lines := strings.Split(s, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return false
		}
		kind := fields[0]
		switch kind {
		case "ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
			"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		default:
			return false
		}
		keyData := fields[1]
		if len(keyData) < 32 {
			return false
		}
		for i := 0; i < len(keyData); i++ {
			c := keyData[i]
			isBase64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
			if !isBase64 {
				return false
			}
		}
		return true
	}
	return false
}

func looksLikeAuthorizedKeys(s string) bool {
	lines := strings.Split(s, "\n")
	found := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return false
		}
		// authorized_keys may start with options; key type is then at fields[1].
		start := 0
		if !isSSHKeyType(fields[0]) {
			start = 1
		}
		if len(fields) <= start+1 || !isSSHKeyType(fields[start]) {
			return false
		}
		if !looksBase64Token(fields[start+1]) {
			return false
		}
		found = true
	}
	return found
}

func looksLikeKnownHosts(s string) bool {
	lines := strings.Split(s, "\n")
	found := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return false
		}
		if !looksLikeKnownHostsHostField(fields[0]) {
			return false
		}
		if !isSSHKeyType(fields[1]) || !looksBase64Token(fields[2]) {
			return false
		}
		found = true
	}
	return found
}

func looksLikeKnownHostsHostField(s string) bool {
	if s == "" || strings.Contains(s, "=") {
		return false
	}
	if strings.HasPrefix(s, "|1|") {
		return true
	}
	return strings.Contains(s, ".") ||
		strings.Contains(s, ":") ||
		strings.Contains(s, ",") ||
		strings.Contains(s, "[") ||
		strings.Contains(s, "]") ||
		strings.Contains(s, "*") ||
		strings.Contains(s, "?")
}

func isSSHKeyType(kind string) bool {
	switch kind {
	case "ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	default:
		return false
	}
}

func looksBase64Token(s string) bool {
	if len(s) < 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isBase64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
		if !isBase64 {
			return false
		}
	}
	return true
}

func looksLikeMbox(s string) bool {
	if !strings.HasPrefix(s, "From ") {
		return false
	}
	lower := "\n" + strings.ToLower(s)
	hits := 0
	if strings.Contains(lower, "\ndate:") {
		hits++
	}
	if strings.Contains(lower, "\nsubject:") {
		hits++
	}
	if strings.Contains(lower, "\nfrom:") {
		hits++
	}
	if strings.Contains(lower, "\nmessage-id:") {
		hits++
	}
	if strings.Contains(lower, "\ncontent-type:") {
		hits++
	}
	return hits >= 2
}

func looksLikeEMLX(s string) bool {
	lineEnd := strings.IndexAny(s, "\r\n")
	if lineEnd <= 0 {
		return false
	}
	first := strings.TrimSpace(s[:lineEnd])
	if first == "" || len(first) > 12 {
		return false
	}
	for _, c := range first {
		if c < '0' || c > '9' {
			return false
		}
	}

	rest := strings.TrimLeft(s[lineEnd:], "\r\n")
	if rest == "" {
		return false
	}
	lower := "\n" + strings.ToLower(rest)
	hits := 0
	if strings.Contains(lower, "\nfrom:") {
		hits++
	}
	if strings.Contains(lower, "\ndate:") {
		hits++
	}
	if strings.Contains(lower, "\nsubject:") {
		hits++
	}
	if strings.Contains(lower, "\ncontent-type:") {
		hits++
	}
	if strings.Contains(lower, "\nmime-version:") {
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
	if looksLikePython(s) || looksLikePowerShell(s) || looksLikePerl(s) || looksLikeBatch(s) || looksLikeCLang(s, s) != "" {
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
	if strings.Contains(s, " as const") {
		hits++
	}
	return hits >= 2
}

func looksLikeQML(s string) bool {
	hits := 0
	if strings.Contains(s, "\nimport qtquick") || strings.Contains(s, "\nimport qtgraphicaleffects") || strings.Contains(s, "\nimport qtquick.controls") {
		hits++
	}
	if strings.Contains(s, "\nimport qtwebengine") || strings.Contains(s, "\nimport qtqml") {
		hits++
	}
	if strings.Contains(s, "\nproperty ") {
		hits++
	}
	if strings.Contains(s, "\nid: ") {
		hits++
	}
	if strings.Contains(s, "\nanchors.") {
		hits++
	}
	if strings.Contains(s, " onclicked:") || strings.Contains(s, " ontriggered:") || strings.Contains(s, "\nsignal ") {
		hits++
	}
	if strings.Contains(s, "rectangle {") || strings.Contains(s, "item {") || strings.Contains(s, "component {") {
		hits++
	}
	if strings.Contains(s, "listview {") || strings.Contains(s, "loader {") || strings.Contains(s, "mousearea {") || strings.Contains(s, "text {") {
		hits++
	}
	return hits >= 2
}

func looksLikeRuby(s string) bool {
	hits := 0
	rubySpecific := 0

	if strings.Contains(s, "\nrequire '") || strings.Contains(s, "\nrequire \"") {
		hits++
		rubySpecific++
	}
	if strings.Contains(s, "\nmodule ") {
		hits++
	}
	if strings.Contains(s, "\nclass ") {
		hits++
	}
	if strings.Contains(s, "\ndef ") {
		hits++
	}
	if strings.Contains(s, " do |") {
		hits++
		rubySpecific++
	}
	if strings.Contains(s, "\nputs ") || strings.Contains(s, "\nattr_accessor ") {
		hits++
		rubySpecific++
	}
	if strings.Contains(s, "\nunless ") || strings.Contains(s, "\nelsif ") {
		hits++
		rubySpecific++
	}
	if strings.Contains(s, "\nbegin\n") && strings.Contains(s, "\nrescue ") {
		hits++
		rubySpecific++
	}
	if strings.Contains(s, "\nend\n") || strings.HasSuffix(strings.TrimSpace(s), "end") {
		hits++
	}

	return hits >= 3 && rubySpecific >= 1
}

func looksLikeCLang(s string, sLower string) string {
	lines := strings.Split(s, "\n")
	preproc := 0
	cHits := 0
	cppHits := 0
	protoHits := 0

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#include") ||
			strings.HasPrefix(line, "#define") ||
			strings.HasPrefix(line, "#ifdef") ||
			strings.HasPrefix(line, "#ifndef") ||
			strings.HasPrefix(line, "#endif") ||
			strings.HasPrefix(line, "#pragma") {
			preproc++
		}

		if strings.HasPrefix(line, "typedef ") ||
			strings.HasPrefix(line, "struct ") ||
			strings.HasPrefix(line, "enum ") ||
			strings.Contains(line, "uint8_t") ||
			strings.Contains(line, "uint16_t") ||
			strings.Contains(line, "uint32_t") ||
			strings.Contains(line, "int8_t") ||
			strings.Contains(line, "int16_t") ||
			strings.Contains(line, "int32_t") ||
			strings.Contains(line, "size_t") {
			cHits++
		}

		if strings.Contains(line, "::") ||
			strings.HasPrefix(line, "class ") ||
			strings.HasPrefix(line, "namespace ") ||
			strings.HasPrefix(line, "template<") ||
			strings.Contains(line, "std::") ||
			line == "public:" || line == "private:" || line == "protected:" {
			cppHits++
		}

		if strings.Contains(line, "(") && strings.Contains(line, ")") && strings.HasSuffix(line, ";") {
			protoHits++
		}
	}

	if strings.Contains(sLower, "extern \"c++\"") {
		cppHits += 2
	}
	if strings.Contains(sLower, "extern \"c\"") {
		cHits++
	}

	if preproc > 0 {
		cHits++
	}
	if protoHits >= 2 {
		cHits++
	}

	if cppHits >= 1 && cHits >= 2 {
		return "C++ source"
	}
	if cHits >= 3 {
		return "C source"
	}
	return ""
}

func looksLikePython(s string) bool {
	if looksLikeQML(s) {
		return false
	}

	structuralHits := 0
	hits := 0
	if strings.Count(s, "\ndef ") > 0 {
		hits++
		structuralHits++
	}
	if strings.Count(s, "\nclass ") > 0 {
		hits++
		structuralHits++
	}
	if strings.Count(s, "\nfrom ") > 0 && strings.Contains(s, " import ") {
		hits++
		structuralHits++
	}
	if importCount := strings.Count(s, "\nimport "); importCount > 0 {
		// Multiple import statements are a strong Python signal.
		hits += minInt(importCount, 2)
	}
	if strings.Contains(s, "\nif __name__ == \"__main__\":") || strings.Contains(s, "\nif __name__ == '__main__':") {
		hits++
		structuralHits++
	}
	if strings.Contains(s, "\nself.") || strings.Contains(s, "\nexcept ") || strings.Contains(s, "\ntry:") {
		structuralHits++
	}
	// Avoid classifying files based only on import lines.
	return hits >= 2 && structuralHits >= 1
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func looksLikePowerShell(s string) bool {
	hits := 0

	// Named block structure.
	if strings.Contains(s, "\nfunction ") {
		hits++
	}
	if strings.Contains(s, "\nparam(") || strings.Contains(s, "\nparam (") {
		hits++
	}
	if strings.Contains(s, "\n$") {
		hits++
	}

	// Write-* family.
	if strings.Contains(s, "write-host") || strings.Contains(s, "write-output") ||
		strings.Contains(s, "write-verbose") || strings.Contains(s, "write-error") {
		hits++
	}

	// [CmdletBinding()] and [Parameter(] are PS-specific attributes.
	if strings.Contains(s, "[cmdletbinding(") || strings.Contains(s, "[parameter(") {
		hits += 2
	}

	// begin/process/end are PS advanced-function block keywords.
	if strings.Contains(s, "\nbegin {") || strings.Contains(s, "\nprocess {") || strings.Contains(s, "\nend {") {
		hits++
	}

	// PS automatic variables — fully unique to PowerShell.
	if strings.Contains(s, "$psscriptroot") || strings.Contains(s, "$pscommandpath") ||
		strings.Contains(s, "$psversiontable") {
		hits += 2
	}

	// $env: colon-in-variable-name syntax is unique to PowerShell.
	if strings.Contains(s, "$env:") {
		hits += 2
	}

	// PS common parameters not found in other languages.
	if strings.Contains(s, "-erroraction") || strings.Contains(s, "-whatif") {
		hits += 2
	}

	// Pipeline variable and PS-specific boolean/null literals.
	if strings.Contains(s, "$_") || strings.Contains(s, "$true") ||
		strings.Contains(s, "$false") || strings.Contains(s, "$null") {
		hits++
	}

	// -join / -split are PS binary operators (spaces required to avoid word fragments).
	if strings.Contains(s, " -join ") || strings.Contains(s, " -split ") {
		hits++
	}

	// @{} hashtable and @() array subexpression literals — PS-specific syntax.
	if strings.Contains(s, "@{") || strings.Contains(s, "@(") {
		hits++
	}

	// Broad Verb-Noun cmdlet pattern.
	if strings.Contains(s, "get-") || strings.Contains(s, "set-") || strings.Contains(s, "new-") ||
		strings.Contains(s, "remove-") || strings.Contains(s, "stop-") || strings.Contains(s, "start-") ||
		strings.Contains(s, "invoke-") || strings.Contains(s, "test-") || strings.Contains(s, "add-") ||
		strings.Contains(s, "where-object") || strings.Contains(s, "foreach-object") ||
		strings.Contains(s, "select-object") || strings.Contains(s, "sort-object") ||
		strings.Contains(s, "import-") || strings.Contains(s, "out-") {
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

func looksLikePHP(s string) bool {
	if strings.Contains(s, "<?php") {
		return true
	}
	// Deliberately avoid bare "<?" to reduce XML false positives.
	return false
}

func looksLikeASPX(s string) bool {
	if strings.Contains(s, "<asp:") {
		return true
	}
	if !strings.Contains(s, "<%@ page") {
		return false
	}
	return strings.Contains(s, "runat=\"server\"") ||
		strings.Contains(s, "codebehind=") ||
		strings.Contains(s, "inherits=") ||
		strings.Contains(s, "masterpagefile=")
}

func looksLikeClassicASP(s string) bool {
	if !strings.Contains(s, "<%") {
		return false
	}
	hits := 0
	if strings.Contains(s, "vbscript") {
		hits++
	}
	if strings.Contains(s, "option explicit") {
		hits++
	}
	if strings.Contains(s, "response.write") {
		hits++
	}
	return hits >= 1
}

func looksLikeJSP(s string) bool {
	if strings.Contains(s, "<jsp:") {
		return true
	}
	if !strings.Contains(s, "<%@ page") {
		return false
	}
	return strings.Contains(s, "import=\"java.") ||
		strings.Contains(s, "contenttype=") ||
		strings.Contains(s, "pageencoding=") ||
		strings.Contains(s, "session=")
}

func looksLikeApacheConfig(s string) bool {
	hits := 0
	if strings.Contains(s, "\nrewriteengine ") {
		hits++
	}
	if strings.Contains(s, "\nrewriterule ") {
		hits++
	}
	if strings.Contains(s, "\ndocumentroot ") {
		hits++
	}
	if strings.Contains(s, "\ndirectoryindex ") {
		hits++
	}
	return hits >= 2
}

func looksLikeNginxConfig(s string) bool {
	hits := 0
	if strings.Contains(s, "\nserver {") {
		hits++
	}
	if strings.Contains(s, "\nlocation {") || strings.Contains(s, "\nlocation /") {
		hits++
	}
	if strings.Contains(s, "\nproxy_pass ") {
		hits++
	}
	if strings.Contains(s, "\nlisten ") {
		hits++
	}
	return hits >= 2
}

func looksLikeIISWebConfig(s string) bool {
	return strings.Contains(s, "<configuration") && strings.Contains(s, "<system.webserver")
}

func looksLikeBatch(s string) bool {
	lines := strings.Split(s, "\n")
	commandHits := 0
	varHits := 0
	hasEchoOff := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "@") {
			line = strings.TrimSpace(line[1:])
		}
		if line == "" {
			continue
		}

		switch {
		case line == "echo off":
			hasEchoOff = true
			commandHits += 2
		case strings.HasPrefix(line, "echo "):
			commandHits++
		case line == "rem" || strings.HasPrefix(line, "rem ") || strings.HasPrefix(line, "::"):
			commandHits++
		case strings.HasPrefix(line, "setlocal"), strings.HasPrefix(line, "endlocal"):
			commandHits++
		case strings.HasPrefix(line, "if exist "), strings.HasPrefix(line, "if not exist "):
			commandHits++
		case strings.HasPrefix(line, "goto "), strings.HasPrefix(line, "call "):
			commandHits++
		case looksLikeBatchForLoop(line), line == "shift", strings.HasPrefix(line, "shift "):
			commandHits++
		case strings.HasPrefix(line, ":"):
			// Label target, common in batch control flow.
			commandHits++
		}

		if strings.Contains(line, "%0") ||
			strings.Contains(line, "%1") ||
			strings.Contains(line, "%2") ||
			strings.Contains(line, "%~") ||
			strings.Contains(line, "%%") ||
			hasDelayedExpansion(line) {
			varHits++
		}
	}

	if hasEchoOff && (commandHits >= 3 || varHits > 0) {
		return true
	}
	if commandHits >= 3 && varHits > 0 {
		return true
	}
	return commandHits >= 5
}

func looksLikeBatchForLoop(line string) bool {
	if !strings.HasPrefix(line, "for ") {
		return false
	}
	rest := strings.TrimSpace(line[len("for "):])
	return strings.HasPrefix(rest, "%%") || strings.HasPrefix(rest, "%") || strings.HasPrefix(rest, "/")
}

func hasDelayedExpansion(line string) bool {
	first := strings.IndexByte(line, '!')
	if first < 0 {
		return false
	}
	last := strings.LastIndexByte(line, '!')
	if last <= first+1 {
		return false
	}
	token := strings.TrimSpace(line[first+1 : last])
	if token == "" {
		return false
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func looksLikeINI(s string) (bool, bool) {
	sLower := "\n" + strings.ToLower(s)
	if looksLikePowerShell(sLower) || looksLikePython(sLower) || looksLikePerl(sLower) || looksLikeBatch(sLower) || looksLikeQML(sLower) {
		return false, false
	}

	lines := strings.Split(s, "\n")
	sections := 0
	keyvals := 0
	hasExtensions := false
	nonComment := 0
	structured := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		nonComment++

		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end > 1 && isValidINISectionLine(line, end) {
				section := strings.TrimSpace(line[1:end])
				if !isLikelyINISectionName(section) {
					continue
				}
				sections++
				structured++
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
				structured++
			}
		}
	}

	if !(sections > 0 && keyvals >= 2) {
		return false, false
	}
	// Require mostly structured INI-style lines to avoid over-classifying plain text.
	if nonComment > 0 && structured*100/nonComment < 70 {
		return false, false
	}
	return true, hasExtensions
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
	firstNonEmptySeen := false
	nonEmpty := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		nonEmpty++
		if line == "---" {
			if !firstNonEmptySeen {
				startMarker = true
			}
			firstNonEmptySeen = true
			continue
		}
		if !firstNonEmptySeen {
			firstNonEmptySeen = true
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
		value := strings.TrimSpace(line[colon+1:])
		if key == "" || value == "" || !isLikelyYAMLKey(key) {
			continue
		}
		keyValLines++
	}

	if nonEmpty == 0 {
		return false
	}
	keyRatio := float64(keyValLines) / float64(nonEmpty)

	if startMarker && keyValLines >= 1 && keyRatio >= 0.2 {
		return true
	}
	return keyValLines >= 3 && keyRatio >= 0.6
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
	candidateLines := 0
	structuredLines := 0
	maxLines := 60

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		candidateLines++
		if candidateLines > maxLines {
			break
		}
		if !strings.ContainsRune(line, delim) {
			continue
		}

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
		if len(fields) < 2 {
			continue
		}
		structuredLines++
		if len(fields) < 3 {
			continue
		}

		validRows = append(validRows, fields)
		fieldCountHits[len(fields)]++
	}

	valid := len(validRows)
	if candidateLines < 4 || structuredLines < 4 || valid < 4 {
		return 0
	}

	// Avoid classifying prose with occasional commas/tabs as delimited text.
	structuredCoverage := float64(structuredLines) / float64(candidateLines)
	if structuredCoverage < 0.75 {
		return 0
	}
	modeEligibleCoverage := float64(valid) / float64(structuredLines)
	if modeEligibleCoverage < 0.7 {
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

func isLikelyYAMLKey(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 64 {
		return false
	}
	if strings.ContainsAny(key, "{}[];,") || strings.HasPrefix(key, "-") {
		return false
	}

	words := strings.Fields(key)
	if len(words) > 3 {
		return false
	}

	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '_', '-', '.', ' ':
			continue
		default:
			return false
		}
	}
	return true
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

func looksLikeGo(s string) bool {
	lines := strings.Split(s, "\n")
	hasPackage := false
	hits := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "package ") && !hasPackage {
			hasPackage = true
			continue
		}
		if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import(") {
			hits++
		}
		if strings.HasPrefix(line, "func ") {
			hits++
		}
		if strings.Contains(line, ":=") {
			hits++
		}
		if strings.HasPrefix(line, "var ") || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "const ") {
			hits++
		}
	}
	return hasPackage && hits >= 1
}

func looksLikeRust(s string) bool {
	hits := 0
	rubySpecificAbsent := !strings.Contains(s, "\nrequire '") && !strings.Contains(s, "\nrequire \"")
	if !rubySpecificAbsent {
		return false
	}
	if strings.Contains(s, "\nfn ") || strings.Contains(s, "\npub fn ") {
		hits++
	}
	if strings.Contains(s, "\nuse std::") || strings.Contains(s, "\nuse crate::") {
		hits++
	}
	if strings.Contains(s, "let mut ") {
		hits++
	}
	if strings.Contains(s, "\nimpl ") || strings.Contains(s, "\npub impl ") {
		hits++
	}
	if strings.Contains(s, "\ntrait ") || strings.Contains(s, "\npub trait ") {
		hits++
	}
	if strings.Contains(s, "#[derive(") || strings.Contains(s, "#[allow(") || strings.Contains(s, "#[cfg(") {
		hits++
	}
	if strings.Contains(s, "-> ") && strings.Contains(s, "{") {
		hits++
	}
	return hits >= 3
}

func looksLikeJava(s string, sLower string) bool {
	if looksLikeCLang(s, sLower) != "" {
		return false
	}
	hits := 0
	if strings.Contains(sLower, "\npublic class ") || strings.Contains(sLower, "\npublic abstract class ") ||
		strings.Contains(sLower, "\npublic interface ") || strings.Contains(sLower, "\npublic enum ") {
		hits += 2
	}
	if strings.Contains(sLower, "\nimport java.") || strings.Contains(sLower, "\nimport javax.") ||
		strings.Contains(sLower, "\nimport org.") || strings.Contains(sLower, "\nimport com.") ||
		strings.Contains(sLower, "\nimport android.") {
		hits++
	}
	if strings.Contains(sLower, "public static void main") {
		hits++
	}
	if strings.Contains(sLower, "@override") || strings.Contains(sLower, "@suppresswarnings") {
		hits++
	}
	if strings.Contains(sLower, "system.out.println") || strings.Contains(sLower, "system.err.println") {
		hits++
	}
	return hits >= 2
}

func looksLikeDockerfile(s string, sLower string) bool {
	lines := strings.Split(s, "\n")
	directives := 0
	hasFrom := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "FROM "):
			hasFrom = true
			directives++
		case strings.HasPrefix(upper, "RUN "), strings.HasPrefix(upper, "COPY "),
			strings.HasPrefix(upper, "ADD "), strings.HasPrefix(upper, "ENV "),
			strings.HasPrefix(upper, "EXPOSE "), strings.HasPrefix(upper, "WORKDIR "),
			strings.HasPrefix(upper, "ENTRYPOINT "), strings.HasPrefix(upper, "CMD "),
			strings.HasPrefix(upper, "LABEL "), strings.HasPrefix(upper, "USER "),
			strings.HasPrefix(upper, "VOLUME "), strings.HasPrefix(upper, "ARG "),
			strings.HasPrefix(upper, "SHELL "), strings.HasPrefix(upper, "HEALTHCHECK "),
			strings.HasPrefix(upper, "ONBUILD "), strings.HasPrefix(upper, "STOPSIGNAL "):
			directives++
		}
	}
	return hasFrom && directives >= 2
}

func looksLikeMakefile(s string) bool {
	lines := strings.Split(s, "\n")
	targets := 0
	recipes := 0
	for i, raw := range lines {
		if len(raw) > 0 && raw[0] == '\t' {
			recipes++
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Target or variable assignment lines.
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "http") {
			col := strings.Index(line, ":")
			target := strings.TrimSpace(line[:col])
			if target != "" && !strings.Contains(target, " ") && i > 0 {
				targets++
			}
		}
	}
	return targets >= 1 && recipes >= 2
}

func looksLikeTOML(s string) bool {
	lines := strings.Split(s, "\n")
	tomlHits := 0
	keyvals := 0
	hasArrayTable := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// [[array of tables]] is unique to TOML.
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			hasArrayTable = true
			tomlHits += 2
			continue
		}
		// [table] header.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.HasPrefix(line, "[[") {
			tomlHits++
			continue
		}
		eq := strings.Index(line, " = ")
		if eq <= 0 {
			continue
		}
		val := strings.TrimSpace(line[eq+3:])
		// Strongly-typed TOML values: booleans, inline arrays, inline tables, datetime.
		if val == "true" || val == "false" {
			tomlHits++
			keyvals++
		} else if strings.HasPrefix(val, "[") || strings.HasPrefix(val, "{") {
			tomlHits++
			keyvals++
		} else if len(val) >= 10 && val[4] == '-' && val[7] == '-' {
			// Date-like: 1979-05-27
			tomlHits++
			keyvals++
		} else {
			keyvals++
		}
	}
	if hasArrayTable {
		return tomlHits >= 3
	}
	return tomlHits >= 4 && keyvals >= 3
}
