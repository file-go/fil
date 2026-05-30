package main

import (
	"bytes"
	"os"
	"strings"
)

var matcherIndd = fileMatcher{
	name:   "indd",
	minLen: 16,
	mime:   "application/x-indesign",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		// Adobe InDesign binary document signature.
		sig := []byte{0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5, 0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D}
		return lenb >= len(sig) && bytes.Equal(b[:len(sig)], sig)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Adobe InDesign document"
	},
}

var matcherDwg = fileMatcher{
	name:   "dwg",
	minLen: 6,
	mime:   "image/vnd.dwg",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 6 && HasPrefix(b, "AC10") && isDigitByte(b[4]) && isDigitByte(b[5])
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AutoCAD DWG drawing"
	},
}

var matcherDxf = fileMatcher{
	name:   "dxf",
	minLen: 12,
	mime:   "image/vnd.dxf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return looksLikeDXFDocument(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AutoCAD DXF drawing exchange format"
	},
}

var matcherStep = fileMatcher{
	name:   "step",
	minLen: 16,
	mime:   "model/step",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 16 || !isText(b) {
			return false
		}
		end := lenb
		if end > 8192 {
			end = 8192
		}
		s := bytes.ToUpper(bytes.TrimSpace(stripUTF8BOM(b[:end])))
		return bytes.HasPrefix(s, []byte("ISO-10303-21;"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "STEP CAD model"
	},
}

var matcherScribus = fileMatcher{
	name:   "scribus",
	minLen: 16,
	mime:   "application/vnd.scribus",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 16 || !isText(b) {
			return false
		}
		end := lenb
		if end > 8192 {
			end = 8192
		}
		s := bytes.ToLower(stripUTF8BOM(b[:end]))
		return bytes.Contains(s, []byte("<scribusutf8new"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Scribus document"
	},
}

var matcherShapefile = fileMatcher{
	name:   "shapefile",
	minLen: 36,
	mime:   "application/x-esri-shape",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 36 || !HasPrefix(b, "\x00\x00\x27\x0A") {
			return false
		}
		// ESRI shapefile version is little-endian 1000 at offset 28.
		if peekLe(b[28:], 4) != 1000 {
			return false
		}
		shapeType := peekLe(b[32:], 4)
		return shapeType >= 0 && shapeType <= 31
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ESRI Shapefile data"
	},
}

var matcherLas = fileMatcher{
	name:   "las",
	minLen: 4,
	mime:   "application/vnd.las",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "LASF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ASPRS LAS LiDAR data"
	},
}

var matcherGeoPackage = fileMatcher{
	name:   "geopackage",
	minLen: 72,
	mime:   "application/geopackage+sqlite3",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 72 || !HasPrefix(b, "SQLite format 3\x00") {
			return false
		}
		// SQLite application_id at offset 68 (big-endian) is 'GPKG'.
		return bytes.Equal(b[68:72], []byte("GPKG"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "OGC GeoPackage database"
	},
}

func looksLikeDXFDocument(b []byte) bool {
	if len(b) < 12 || !isText(b) {
		return false
	}
	end := len(b)
	if end > 8192 {
		end = 8192
	}
	s := stripUTF8BOM(b[:end])
	s = bytes.ReplaceAll(s, []byte("\r\n"), []byte("\n"))
	s = bytes.TrimSpace(s)
	if len(s) == 0 {
		return false
	}
	l := strings.ToLower(string(s))
	return strings.HasPrefix(l, "0\nsection") && strings.Contains(l, "\nheader")
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}
