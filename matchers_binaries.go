package main

import "os"

var matcherElf = fileMatcher{
	name:   "elf",
	minLen: 45,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 45 && HasPrefix(b, "\x7FELF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Elf file " + doElf(b)
	},
}

var matcherJavaClass = fileMatcher{
	name:   "java-class",
	minLen: 9,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 8 && HasPrefix(b, "\xca\xfe\xba\xbe")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java class file"
	},
}

var matcherDex = fileMatcher{
	name:   "dex",
	minLen: 9,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 8 && HasPrefix(b, "dex\n")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Android dex file"
	},
}

var matcherWasm = fileMatcher{
	name:   "wasm",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x00asm")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WebAssembly binary"
	},
}

var matcherMacho = fileMatcher{
	name:   "macho",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && Equal(b[1:4], "\xfa\xed\xfe")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Mach-O"
	},
}

var matcherLlvmBitcode = fileMatcher{
	name:   "llvm-bitcode",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 4 && HasPrefix(b, "BC\xc0\xde")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LLVM IR bitcode"
	},
}

var matcherPem = fileMatcher{
	name:   "pem",
	minLen: len("-----BEGIN CERTIFICATE-----"),
	match: func(b []byte, lenb int, magic int) bool {
		return HasPrefix(b, "-----BEGIN CERTIFICATE-----")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PEM certificate"
	},
}

var matcherPe = fileMatcher{
	name:   "pe",
	minLen: 64,
	match: func(b []byte, lenb int, magic int) bool {
		return magic != -1 && HasPrefix(b, "MZ") && magic < lenb-4 &&
			Equal(b[magic:magic+4], "\x50\x45\x00\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describePE(b, magic)
	},
}

var matcherIso9660 = fileMatcher{
	name:   "iso9660",
	minLen: 0x8006,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 0x8006 && Equal(b[0x8001:0x8006], "CD001")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ISO 9660 CD-ROM filesystem"
	},
}
