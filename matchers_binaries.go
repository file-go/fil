package main

import (
	"bytes"
	"os"
)

var matcherElf = fileMatcher{
	name:   "elf",
	minLen: 45,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 45 && HasPrefix(b, "\x7FELF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Elf file " + doElf(b)
	},
}

var matcherJavaClass = fileMatcher{
	name:   "java-class",
	minLen: 9,
	mime:   "application/java",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 8 && HasPrefix(b, "\xca\xfe\xba\xbe")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java class file"
	},
}

var matcherJavaSerialization = fileMatcher{
	name:   "java-serialization",
	minLen: 4,
	mime:   "application/x-java-serialized-object",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\xAC\xED\x00\x05")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java serialized object"
	},
}

var matcherDex = fileMatcher{
	name:   "dex",
	minLen: 9,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 8 && HasPrefix(b, "dex\n")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Android dex file"
	},
}

var matcherJmod = fileMatcher{
	name:   "jmod",
	minLen: 4,
	mime:   "application/x-java-jmod",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "JMOD")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java JMOD module"
	},
}

var matcherHprof = fileMatcher{
	name:   "hprof",
	minLen: len("JAVA PROFILE "),
	mime:   "application/x-java-hprof",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= len("JAVA PROFILE ") && HasPrefix(b, "JAVA PROFILE ")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Java HPROF heap dump"
	},
}

var matcherWasm = fileMatcher{
	name:   "wasm",
	minLen: 4,
	mime:   "application/wasm",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x00asm")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WebAssembly binary"
	},
}

var matcherJavaKeyStore = fileMatcher{
	name:   "java-keystore",
	minLen: 12,
	mime:   "application/x-java-keystore",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "application/x-mach-binary",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 32 && Equal(b[1:4], "\xfa\xed\xfe")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Mach-O"
	},
}

var matcherLlvmBitcode = fileMatcher{
	name:   "llvm-bitcode",
	minLen: 5,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 4 && HasPrefix(b, "BC\xc0\xde")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LLVM IR bitcode"
	},
}

var matcherPem = fileMatcher{
	name:   "pem",
	minLen: len("-----BEGIN "),
	mime:   "", // dynamic: certificate request → application/pkcs10, all others → application/x-pem-file
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return detectPEMDescription(b) != ""
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return detectPEMDescription(b)
	},
}

var matcherPkcs12 = fileMatcher{
	name:   "pkcs12",
	minLen: 24,
	mime:   "application/x-pkcs12",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 24 || b[0] != 0x30 {
			return false
		}
		end := lenb
		if end > 512 {
			end = 512
		}
		s := b[:end]
		// PFX version INTEGER 3 and ContentInfo with data OID.
		if !bytes.Contains(s, []byte{0x02, 0x01, 0x03}) {
			return false
		}
		return bytes.Contains(s, []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01})
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PKCS#12 key store"
	},
}

var matcherDerX509Cert = fileMatcher{
	name:   "der-x509-cert",
	minLen: 32,
	mime:   "application/pkix-cert",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 32 || b[0] != 0x30 {
			return false
		}
		end := lenb
		if end > 2048 {
			end = 2048
		}
		s := b[:end]
		// Typical certificate name and extension OIDs.
		hasName := bytes.Contains(s, []byte{0x06, 0x03, 0x55, 0x04, 0x03})
		hasExt := bytes.Contains(s, []byte{0x06, 0x03, 0x55, 0x1D, 0x13}) ||
			bytes.Contains(s, []byte{0x06, 0x03, 0x55, 0x1D, 0x0F}) ||
			bytes.Contains(s, []byte{0x06, 0x03, 0x55, 0x1D, 0x11})
		return hasName && hasExt
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "X.509 certificate (DER)"
	},
}

var matcherPkcs8Der = fileMatcher{
	name:   "pkcs8-der",
	minLen: 24,
	mime:   "application/pkcs8",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 24 || b[0] != 0x30 {
			return false
		}
		end := lenb
		if end > 1024 {
			end = 1024
		}
		s := b[:end]
		verPos := bytes.Index(s, []byte{0x02, 0x01, 0x00})
		if verPos == -1 || verPos > 16 {
			return false
		}
		keyOIDPos := indexAnyOID(s, [][]byte{
			{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}, // rsaEncryption
			{0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01},             // id-ecPublicKey
			{0x06, 0x03, 0x2B, 0x65, 0x70},                                     // Ed25519
		})
		if keyOIDPos == -1 {
			return false
		}
		octetPos := bytes.IndexByte(s[keyOIDPos:], 0x04)
		return octetPos > 0 && octetPos < 128
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PKCS#8 private key (DER)"
	},
}

var matcherSpkiDer = fileMatcher{
	name:   "spki-der",
	minLen: 20,
	mime:   "application/pkix-key",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 20 || b[0] != 0x30 {
			return false
		}
		end := lenb
		if end > 1024 {
			end = 1024
		}
		s := b[:end]
		if bytes.Contains(s, []byte{0x06, 0x03, 0x55, 0x04, 0x03}) {
			// Likely a certificate distinguished name, not bare SPKI.
			return false
		}
		keyOIDPos := indexAnyOID(s, [][]byte{
			{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}, // rsaEncryption
			{0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01},             // id-ecPublicKey
			{0x06, 0x03, 0x2B, 0x65, 0x70},                                     // Ed25519
		})
		if keyOIDPos == -1 {
			return false
		}
		bitStringPos := bytes.IndexByte(s[keyOIDPos:], 0x03)
		return bitStringPos > 0 && bitStringPos < 128
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "X.509 SubjectPublicKeyInfo (DER public key)"
	},
}

var matcherPkcs7Der = fileMatcher{
	name:   "pkcs7-der",
	minLen: 20,
	mime:   "application/pkcs7-signature",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "RGDB")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "CRDA wireless regulatory database file"
	},
}

var matcherPe = fileMatcher{
	name:   "pe",
	minLen: 64,
	mime:   "application/vnd.microsoft.portable-executable",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "application/x-object",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "application/x-iso9660-image",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 0x8006 && Equal(b[0x8001:0x8006], "CD001")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ISO 9660 CD-ROM filesystem"
	},
}

var matcherLuks = fileMatcher{
	name:   "luks",
	minLen: 6,
	mime:   "application/x-luks",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 6 && HasPrefix(b, "LUKS\xBA\xBE")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LUKS encrypted volume"
	},
}

var matcherDtb = fileMatcher{
	name:   "dtb",
	minLen: 4,
	mime:   "application/x-dtb",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\xD0\x0D\xFE\xED")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Device Tree Blob"
	},
}

var matcherAndroidBoot = fileMatcher{
	name:   "android-boot",
	minLen: 8,
	mime:   "application/vnd.android.boot-image",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "ANDROID!")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Android boot image"
	},
}

var matcherPgp = fileMatcher{
	name:   "pgp",
	minLen: 15,
	mime:   "", // dynamic: keys, messages, signatures have different MIMEs
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb >= 15 && HasPrefix(b, "-----BEGIN PGP ") {
			return true
		}
		// Binary OpenPGP: 0x99 is old-format public-key packet (most common export)
		return lenb >= 3 && b[0] == 0x99 && b[1] != 0x00
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		switch {
		case HasPrefix(b, "-----BEGIN PGP PUBLIC KEY BLOCK-----"):
			return "PGP public key block"
		case HasPrefix(b, "-----BEGIN PGP PRIVATE KEY BLOCK-----"):
			return "PGP private key block"
		case HasPrefix(b, "-----BEGIN PGP SIGNED MESSAGE-----"):
			return "PGP signed message"
		case HasPrefix(b, "-----BEGIN PGP MESSAGE-----"):
			return "PGP message"
		case HasPrefix(b, "-----BEGIN PGP SIGNATURE-----"):
			return "PGP signature"
		case HasPrefix(b, "-----BEGIN PGP "):
			return "PGP armored data"
		default:
			return "PGP binary data"
		}
	},
}

var matcherDosMbrBootSector = fileMatcher{
	name:   "dos-mbr-boot-sector",
	minLen: 512,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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

func detectPEMDescription(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	end := len(b)
	if end > 512 {
		end = 512
	}
	s := b[:end]
	if len(s) >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		s = s[3:]
	}
	s = bytes.TrimLeft(s, " \t\r\n")
	if len(s) < len("-----BEGIN ") || !bytes.HasPrefix(s, []byte("-----BEGIN ")) {
		return ""
	}

	lineEnd := bytes.IndexByte(s, '\n')
	if lineEnd == -1 {
		lineEnd = len(s)
	}
	line := bytes.TrimRight(s[:lineEnd], "\r")

	switch {
	case bytes.Equal(line, []byte("-----BEGIN CERTIFICATE-----")):
		return "PEM certificate"
	case bytes.Equal(line, []byte("-----BEGIN CERTIFICATE REQUEST-----")),
		bytes.Equal(line, []byte("-----BEGIN NEW CERTIFICATE REQUEST-----")):
		return "PEM certificate request"
	case bytes.Equal(line, []byte("-----BEGIN PUBLIC KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN RSA PUBLIC KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN SSH2 PUBLIC KEY-----")):
		return "PEM public key"
	case bytes.Equal(line, []byte("-----BEGIN PRIVATE KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN RSA PRIVATE KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN DSA PRIVATE KEY-----")),
		bytes.Equal(line, []byte("-----BEGIN EC PRIVATE KEY-----")):
		return "PEM private key"
	case bytes.Equal(line, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")):
		return "OpenSSH private key"
	case bytes.Equal(line, []byte("-----BEGIN PKCS7-----")):
		return "PEM PKCS#7 message"
	default:
		return ""
	}
}

func indexAnyOID(s []byte, oids [][]byte) int {
	for _, oid := range oids {
		if i := bytes.Index(s, oid); i >= 0 {
			return i
		}
	}
	return -1
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
