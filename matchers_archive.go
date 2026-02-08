package main

import "os"

var matcherAr = fileMatcher{
	name:   "ar",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "!<arch>\n")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ar archive"
	},
}

var matcherTar = fileMatcher{
	name:   "tar",
	minLen: 501,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 500 && Equal(b[257:262], "ustar")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return doTar(file)
	},
}

var matcherZip = fileMatcher{
	name:   "zip",
	minLen: 6,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 5 && HasPrefix(b, "PK\x03\x04")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return doZip(file)
	},
}

var matcherDmg = fileMatcher{
	name:   "dmg",
	minLen: 1,
	match: func(b []byte, lenb int, magic int) bool {
		return hasDmgTrailer()
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple UDIF disk image"
	},
}

var matcherVmdk = fileMatcher{
	name:   "vmdk",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "KDMV")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "VMware virtual disk"
	},
}

var matcherBzip2 = fileMatcher{
	name:   "bzip2",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 4 && HasPrefix(b, "BZh")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "bzip2 compressed data"
	},
}

var matcherXz = fileMatcher{
	name:   "xz",
	minLen: 6,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 6 && HasPrefix(b, "\xFD7zXZ\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "XZ compressed data"
	},
}

var matcherZstd = fileMatcher{
	name:   "zstd",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x28\xB5\x2F\xFD")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Zstandard compressed data"
	},
}

var matcherLz4 = fileMatcher{
	name:   "lz4",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x04\x22\x4D\x18")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LZ4 compressed data"
	},
}

var matcherLzip = fileMatcher{
	name:   "lzip",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "LZIP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LZIP compressed data"
	},
}

var matcherGzip = fileMatcher{
	name:   "gzip",
	minLen: 11,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 10 && HasPrefix(b, "\x1f\x8b")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "gzip compressed data"
	},
}

var matcherRar = fileMatcher{
	name:   "rar",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x52\x61\x72\x21\x1A\x07\x01\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "RAR archive data"
	},
}

var matcher7zip = fileMatcher{
	name:   "7zip",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x37\x7A\xBC\xAF\x27\x1C")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "7zip archive data"
	},
}

var matcherCab = fileMatcher{
	name:   "cab",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x4D\x53\x43\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Cabinet file"
	},
}
