package main

import (
	"bytes"
	"os"
)

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

var matcherJavaKeyStore = fileMatcher{
	name:   "java-keystore",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 12 {
			return false
		}
		// JKS and JCEKS magic numbers.
		if !(HasPrefix(b, "\xFE\xED\xFE\xED") || HasPrefix(b, "\xCE\xCE\xCE\xCE")) {
			return false
		}
		version := peekBe(b[4:], 4)
		// Common versions are 1 and 2.
		if version != 1 && version != 2 {
			return false
		}
		entries := peekBe(b[8:], 4)
		return entries >= 0
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		if HasPrefix(b, "\xCE\xCE\xCE\xCE") {
			return "Java JCEKS keystore"
		}
		return "Java JKS keystore"
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

var matcherPkcs7Der = fileMatcher{
	name:   "pkcs7-der",
	minLen: 20,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 20 || b[0] != 0x30 {
			return false
		}
		// OID 1.2.840.113549.1.7.2 (signedData) inside ContentInfo.
		return bytes.Contains(b[:minInt(lenb, 512)], []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02})
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "DER Encoded PKCS#7 Signed Data"
	},
}

var matcherCrdaRegdb = fileMatcher{
	name:   "crda-regdb",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "RGDB")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "CRDA wireless regulatory database file"
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

var matcherCoffObject = fileMatcher{
	name:   "coff-object",
	minLen: 20,
	match: func(b []byte, lenb int, magic int) bool {
		return looksLikeCoffObject(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		machine := peekLe(b[:2], 2)
		switch machine {
		case 0x8664:
			return "x86-64 COFF object file"
		case 0x14c:
			return "Intel i386 COFF object file"
		default:
			return "COFF object file"
		}
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

var matcherDosMbrBootSector = fileMatcher{
	name:   "dos-mbr-boot-sector",
	minLen: 512,
	match: func(b []byte, lenb int, magic int) bool {
		return isDosMbrBootSector(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "DOS/MBR boot sector"
	},
}

func isDosMbrBootSector(b []byte) bool {
	// Bootable ISO images can contain 0x55AA and MBR-like bytes.
	// If ISO9660 primary volume descriptor is present, prefer ISO classification.
	if len(b) >= 0x8006 && Equal(b[0x8001:0x8006], "CD001") {
		return false
	}

	if len(b) < 512 || b[510] != 0x55 || b[511] != 0xAA {
		return false
	}
	return looksLikeFatBootSector(b) || hasLikelyMbrPartitionTable(b)
}

func looksLikeFatBootSector(b []byte) bool {
	if len(b) < 64 {
		return false
	}

	hasJump := (b[0] == 0xEB && b[2] == 0x90) || b[0] == 0xE9
	if !hasJump {
		return false
	}

	bytesPerSector := peekLe(b[11:], 2)
	switch bytesPerSector {
	case 512, 1024, 2048, 4096:
	default:
		return false
	}

	spc := b[13]
	if spc == 0 || (spc&(spc-1)) != 0 {
		return false
	}

	reserved := peekLe(b[14:], 2)
	if reserved <= 0 {
		return false
	}

	numFATs := b[16]
	if numFATs == 0 || numFATs > 4 {
		return false
	}

	return true
}

func hasLikelyMbrPartitionTable(b []byte) bool {
	if len(b) < 512 {
		return false
	}

	nonEmpty := false
	for i := 0; i < 4; i++ {
		off := 446 + i*16
		status := b[off]
		if status != 0x00 && status != 0x80 {
			return false
		}
		if b[off+4] != 0x00 {
			nonEmpty = true
		}
	}

	return nonEmpty
}

func looksLikeCoffObject(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	machine := peekLe(b[:2], 2)
	if machine != 0x14c && machine != 0x8664 {
		return false
	}
	sections := peekLe(b[2:], 2)
	if sections <= 0 || sections > 128 {
		return false
	}
	// COFF object files have no optional header.
	if peekLe(b[16:], 2) != 0 {
		return false
	}
	ptrSym := peekLe(b[8:], 4)
	numSym := peekLe(b[12:], 4)
	if ptrSym < 20 || numSym <= 0 {
		return false
	}
	return true
}
