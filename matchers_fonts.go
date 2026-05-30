package main

import "os"

var matcherWoff = fileMatcher{
	name:   "woff",
	minLen: 4,
	mime:   "font/woff",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "wOFF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WOFF font"
	},
}

var matcherWoff2 = fileMatcher{
	name:   "woff2",
	minLen: 4,
	mime:   "font/woff2",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "wOF2")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WOFF2 font"
	},
}

var matcherOtf = fileMatcher{
	name:   "otf",
	minLen: 4,
	mime:   "font/otf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "OTTO")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "OpenType font data"
	},
}

var matcherEot = fileMatcher{
	name:   "eot",
	minLen: 36,
	mime:   "application/vnd.ms-fontobject",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		// EOT has magic 0x504C ("LP") at offset 34 (little-endian bytes 4C 50).
		if lenb < 36 || b[34] != 0x4C || b[35] != 0x50 {
			return false
		}
		version := peekLe(b[8:], 4)
		switch version {
		case 0x00010000, 0x00020001, 0x00020002, 0x00030001:
			return true
		default:
			return false
		}
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Embedded OpenType font"
	},
}

var matcherTtf = fileMatcher{
	name:   "ttf",
	minLen: 13,
	mime:   "font/ttf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 12 && HasPrefix(b, "\x00\x01\x00\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TrueType font"
	},
}

var matcherTtfCollection = fileMatcher{
	name:   "ttf-collection",
	minLen: 13,
	mime:   "font/collection",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 12 && HasPrefix(b, "ttcf\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TrueType font collection"
	},
}
