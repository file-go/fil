package main

import "os"

var matcherWoff = fileMatcher{
	name:   "woff",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "wOFF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WOFF font"
	},
}

var matcherWoff2 = fileMatcher{
	name:   "woff2",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "wOF2")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WOFF2 font"
	},
}

var matcherTtf = fileMatcher{
	name:   "ttf",
	minLen: 13,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 12 && HasPrefix(b, "\x00\x01\x00\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TrueType font"
	},
}

var matcherTtfCollection = fileMatcher{
	name:   "ttf-collection",
	minLen: 13,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 12 && HasPrefix(b, "ttcf\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TrueType font collection"
	},
}
