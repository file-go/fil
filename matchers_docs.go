package main

import "os"

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
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && (HasPrefix(b, "<!DOCTYPE html") || HasPrefix(b, "<head>"))
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
