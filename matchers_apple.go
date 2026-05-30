package main

import (
	"bytes"
	"os"
)

var matcherXar = fileMatcher{
	name:   "xar",
	minLen: 28,
	mime:   "application/x-xar",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 28 && HasPrefix(b, "xar!")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "XAR archive (Apple installer package)"
	},
}

var matcherAppleBom = fileMatcher{
	name:   "apple-bom",
	minLen: 8,
	mime:   "application/x-apple-bom",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "BOMStore")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple BOM archive"
	},
}

var matcherAppleDouble = fileMatcher{
	name:   "appledouble",
	minLen: 4,
	mime:   "application/applefile",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x00\x05\x16\x07")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AppleDouble encoded file"
	},
}

var matcherApplePlistBinary = fileMatcher{
	name:   "apple-plist-binary",
	minLen: 8,
	mime:   "application/x-plist",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "bplist00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple property list"
	},
}

var matcherApplePlistXML = fileMatcher{
	name:   "apple-plist-xml",
	minLen: 16,
	mime:   "application/x-plist",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 16 || !isText(b) {
			return false
		}
		end := lenb
		if end > 8192 {
			end = 8192
		}
		s := bytes.ToLower(stripUTF8BOM(b[:end]))
		return bytes.Contains(s, []byte("<plist")) &&
			(bytes.Contains(s, []byte("<!doctype plist")) || bytes.Contains(s, []byte("apple computer//dtd plist")))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple property list"
	},
}

var matcherDSStore = fileMatcher{
	name:   "ds-store",
	minLen: 8,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && bytes.Equal(b[:8], []byte{0x00, 0x00, 0x00, 0x01, 'B', 'u', 'd', '1'})
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple DS_Store metadata"
	},
}

var matcherApfs = fileMatcher{
	name:   "apfs",
	minLen: 36,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 36 {
			return false
		}
		// APFS container and volume superblock signatures at offset 32.
		return Equal(b[32:36], "NXSB") || Equal(b[32:36], "APSB")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple APFS filesystem"
	},
}

var matcherHfs = fileMatcher{
	name:   "hfs",
	minLen: 1026,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 1026 {
			return false
		}
		return Equal(b[1024:1026], "BD") || Equal(b[1024:1026], "H+") || Equal(b[1024:1026], "HX")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple HFS/HFS+ filesystem"
	},
}
