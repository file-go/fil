package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

var matcherBmp = fileMatcher{
	name:   "bmp",
	minLen: 51,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 50 && HasPrefix(b, "BM") && Equal(b[6:10], "\x00\x00\x00\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "BMP image"
	},
}

var matcherWmf = fileMatcher{
	name:   "wmf",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 4 {
			return false
		}
		// Placeable WMF.
		if HasPrefix(b, "\xD7\xCD\xC6\x9A") {
			return true
		}
		// Standard WMF.
		return HasPrefix(b, "\x01\x00\x09\x00") || HasPrefix(b, "\x02\x00\x09\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows metafile"
	},
}

var matcherPdf = fileMatcher{
	name:   "pdf",
	minLen: 51,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 50 && HasPrefix(b, "\x25\x50\x44\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PDF document"
	},
}

var matcherMobi = fileMatcher{
	name:   "mobi",
	minLen: 68,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 68 && Equal(b[60:68], "BOOKMOBI")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Mobipocket e-book"
	},
}

var matcherLit = fileMatcher{
	name:   "lit",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "ITOLITLS")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Reader eBook"
	},
}

var matcherTiff = fileMatcher{
	name:   "tiff",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 &&
			(HasPrefix(b, "\x49\x49\x2a\x00") || HasPrefix(b, "\x4D\x4D\x00\x2a"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TIFF image data"
	},
}

var matcherMsi = fileMatcher{
	name:   "msi",
	minLen: 32,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeMsi(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Installer (MSI)"
	},
}

var matcherMsAccess = fileMatcher{
	name:   "ms-access",
	minLen: 64,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 64 || !HasPrefix(b, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
			return false
		}
		end := lenb
		if end > 8192 {
			end = 8192
		}
		h := b[:end]
		return bytes.Contains(h, []byte("Standard Jet DB")) || bytes.Contains(h, []byte("Standard ACE DB"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Access database"
	},
}

var matcherMsg = fileMatcher{
	name:   "msg",
	minLen: 64,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 64 || !HasPrefix(b, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
			return false
		}
		hasProps := sampleContainsASCIIOrUTF16LE(b, "__properties_version1.0", 256*1024)
		hasSubst := sampleContainsASCIIOrUTF16LE(b, "__substg1.0_", 256*1024)
		hasNameID := sampleContainsASCIIOrUTF16LE(b, "__nameid_version1.0", 256*1024)
		return hasProps && (hasSubst || hasNameID)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Outlook MSG message"
	},
}

var matcherOle = fileMatcher{
	name:   "ole",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Office (Legacy format)"
	},
}

var matcherRtf = fileMatcher{
	name:   "rtf",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "\x7B\x5C\x72\x74\x66\x31")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Rich Text Format"
	},
}

var matcherHtml = fileMatcher{
	name:   "html",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeHTMLDocument(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "HTML document"
	},
}

var matcherXml = fileMatcher{
	name:   "xml",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeXMLDocument(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		if looksLikeVMwareVMXF(b) {
			return "VMware supplemental configuration (VMXF)"
		}
		return "XML document"
	},
}

var matcherKml = fileMatcher{
	name:   "kml",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeKMLDocument(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "KML geospatial data"
	},
}

var matcherFb2 = fileMatcher{
	name:   "fb2",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeFB2Document(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "FictionBook e-book"
	},
}

var matcherJnlp = fileMatcher{
	name:   "jnlp",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeJNLPDocument(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java Web Start JNLP file"
	},
}

var matcherSvg = fileMatcher{
	name:   "svg",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 5 || !isText(b) {
			return false
		}
		end := lenb
		if end > 4096 {
			end = 4096
		}
		h := bytes.ToLower(b[:end])
		trimmed := bytes.TrimSpace(h)
		if len(trimmed) == 0 {
			return false
		}
		if !bytes.HasPrefix(trimmed, []byte("<?xml")) && !bytes.HasPrefix(trimmed, []byte("<svg")) {
			return false
		}
		return bytes.Contains(h, []byte("<svg"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "SVG Scalable Vector Graphics image"
	},
}

var matcherJSON = fileMatcher{
	name:   "json",
	minLen: 2,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 2 || !isText(b) {
			return false
		}
		trimmed := bytes.TrimSpace(b)
		if len(trimmed) == 0 {
			return false
		}
		if trimmed[0] != '{' && trimmed[0] != '[' {
			return false
		}
		return json.Valid(trimmed)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "JSON data"
	},
}

func looksLikeHTMLDocument(b []byte) bool {
	if len(b) < 5 || !isText(b) {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	sample := bytes.TrimSpace(b[:end])
	if len(sample) == 0 {
		return false
	}

	utf8Lower := bytes.ToLower(stripUTF8BOM(sample))
	if looksLikeHTMLSample(utf8Lower) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		return looksLikeHTMLSample(bytes.ToLower(bytes.TrimSpace(utf16Decoded)))
	}

	return false
}

func looksLikeKMLDocument(b []byte) bool {
	if len(b) < 12 {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	sample := bytes.TrimSpace(b[:end])
	if len(sample) == 0 {
		return false
	}

	utf8Lower := bytes.ToLower(stripUTF8BOM(sample))
	if hasKMLMarkers(utf8Lower) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		return hasKMLMarkers(bytes.ToLower(bytes.TrimSpace(utf16Decoded)))
	}

	return false
}

func looksLikeFB2Document(b []byte) bool {
	if len(b) < 12 {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	sample := bytes.TrimSpace(b[:end])
	if len(sample) == 0 {
		return false
	}

	utf8Lower := bytes.ToLower(stripUTF8BOM(sample))
	if bytes.Contains(utf8Lower, []byte("<fictionbook")) {
		return true
	}
	if bytes.Contains(utf8Lower, []byte("<description")) && bytes.Contains(utf8Lower, []byte("<body")) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		d := bytes.ToLower(bytes.TrimSpace(utf16Decoded))
		return bytes.Contains(d, []byte("<fictionbook"))
	}

	return false
}

func looksLikeXMLDocument(b []byte) bool {
	if len(b) < 5 {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	sample := bytes.TrimSpace(b[:end])
	if len(sample) == 0 {
		return false
	}

	utf8Sample := bytes.TrimSpace(stripUTF8BOM(sample))
	utf8Lower := bytes.ToLower(utf8Sample)
	if looksLikeXMLSample(utf8Lower) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		decoded := bytes.ToLower(bytes.TrimSpace(utf16Decoded))
		return looksLikeXMLSample(decoded)
	}

	return false
}

func looksLikeXMLSample(s []byte) bool {
	s = bytes.TrimSpace(s)
	if len(s) < 5 {
		return false
	}
	if bytes.HasPrefix(s, []byte("<#")) {
		// PowerShell block comment.
		return false
	}
	if bytes.HasPrefix(s, []byte("<?xml")) {
		return true
	}

	// Skip XML comments at the top and look for an element start.
	if bytes.HasPrefix(s, []byte("<!--")) {
		if end := bytes.Index(s, []byte("-->")); end > 0 && end+3 < len(s) {
			s = bytes.TrimSpace(s[end+3:])
		}
	}

	return startsWithXMLTag(s)
}

func looksLikeJNLPDocument(b []byte) bool {
	if len(b) < 8 {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	sample := bytes.TrimSpace(b[:end])
	if len(sample) == 0 {
		return false
	}

	utf8Sample := bytes.TrimSpace(stripUTF8BOM(sample))
	utf8Lower := bytes.ToLower(utf8Sample)
	if looksLikeXMLSample(utf8Lower) && bytes.Contains(utf8Lower, []byte("<jnlp")) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		decoded := bytes.ToLower(bytes.TrimSpace(utf16Decoded))
		return looksLikeXMLSample(decoded) && bytes.Contains(decoded, []byte("<jnlp"))
	}

	return false
}

func startsWithXMLTag(s []byte) bool {
	if len(s) < 3 || s[0] != '<' {
		return false
	}
	c := s[1]
	if c == '/' || c == '!' || c == '?' || c == '#' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
		return false
	}
	if !isXMLNameStart(c) {
		return false
	}
	close := bytes.IndexByte(s[:minInt(len(s), 512)], '>')
	return close > 2
}

func isXMLNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':'
}

func hasKMLMarkers(s []byte) bool {
	return bytes.Contains(s, []byte("<kml")) && bytes.Contains(s, []byte("xmlns="))
}

func looksLikeVMwareVMXF(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	end := len(b)
	if end > 8192 {
		end = 8192
	}
	top := strings.ToLower(string(bytes.TrimSpace(b[:end])))

	return strings.Contains(top, "<foundry") &&
		strings.Contains(top, "<vm>") &&
		strings.Contains(top, "vmxpathname")
}

func hasHTMLMarkers(s []byte) bool {
	return bytes.Contains(s, []byte("<!doctype html")) ||
		bytes.Contains(s, []byte("<html")) ||
		bytes.Contains(s, []byte("<head")) ||
		bytes.Contains(s, []byte("<body")) ||
		bytes.Contains(s, []byte("<title")) ||
		bytes.Contains(s, []byte("<meta "))
}

func looksLikeHTMLSample(s []byte) bool {
	s = bytes.TrimSpace(s)
	if len(s) < 5 {
		return false
	}
	if !bytes.HasPrefix(s, []byte("<")) {
		return false
	}

	// Skip a leading comment block and re-check.
	if bytes.HasPrefix(s, []byte("<!--")) {
		if end := bytes.Index(s, []byte("-->")); end > 0 && end+3 < len(s) {
			s = bytes.TrimSpace(s[end+3:])
		}
	}

	if bytes.HasPrefix(s, []byte("<!doctype html")) ||
		bytes.HasPrefix(s, []byte("<html")) ||
		bytes.HasPrefix(s, []byte("<head")) ||
		bytes.HasPrefix(s, []byte("<body")) {
		return true
	}

	// XHTML: starts as XML prolog, but should contain <html shortly after.
	if bytes.HasPrefix(s, []byte("<?xml")) {
		end := minInt(len(s), 1024)
		return bytes.Contains(s[:end], []byte("<html"))
	}

	// Keep fallback marker check near beginning only to avoid embedded HTML in binary containers.
	end := minInt(len(s), 1024)
	return hasHTMLMarkers(s[:end])
}

func stripUTF8BOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func decodeUTF16ToASCII(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}

	le := false
	be := false
	start := 0
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		le = true
		start = 2
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		be = true
		start = 2
	default:
		limit := len(b)
		if limit > 256 {
			limit = 256
		}
		evenZero := 0
		oddZero := 0
		for i := 0; i < limit; i++ {
			if b[i] != 0x00 {
				continue
			}
			if i%2 == 0 {
				evenZero++
			} else {
				oddZero++
			}
		}
		if oddZero > evenZero*2 && oddZero >= 8 {
			le = true
		} else if evenZero > oddZero*2 && evenZero >= 8 {
			be = true
		} else {
			return nil, false
		}
	}

	if (len(b)-start) < 4 {
		return nil, false
	}

	out := make([]byte, 0, (len(b)-start)/2)
	printables := 0
	for i := start; i+1 < len(b); i += 2 {
		var ch byte
		var other byte
		if le {
			ch = b[i]
			other = b[i+1]
		} else if be {
			ch = b[i+1]
			other = b[i]
		}
		if other != 0x00 {
			continue
		}
		out = append(out, ch)
		if ch >= 0x20 && ch <= 0x7E {
			printables++
		}
	}

	if len(out) < 4 || printables < 4 {
		return nil, false
	}
	return out, true
}
