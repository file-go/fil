package main

import (
	"bytes"
	"encoding/json"
	"os"
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

var matcherPdf = fileMatcher{
	name:   "pdf",
	minLen: 51,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 50 && HasPrefix(b, "\x25\x50\x44\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PDF image"
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
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "<?xml version")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "XML document"
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

	utf8Lower := bytes.ToLower(stripUTF8BOM(sample))
	if hasHTMLMarkers(utf8Lower) {
		return true
	}

	if utf16Decoded, ok := decodeUTF16ToASCII(sample); ok {
		return hasHTMLMarkers(bytes.ToLower(bytes.TrimSpace(utf16Decoded)))
	}

	return false
}

func hasHTMLMarkers(s []byte) bool {
	return bytes.Contains(s, []byte("<!doctype html")) ||
		bytes.Contains(s, []byte("<html")) ||
		bytes.Contains(s, []byte("<head")) ||
		bytes.Contains(s, []byte("<body")) ||
		bytes.Contains(s, []byte("<title")) ||
		bytes.Contains(s, []byte("<meta "))
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
