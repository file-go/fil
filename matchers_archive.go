package main

import (
	"bytes"
	"os"
)

var matcherAr = fileMatcher{
	name:   "ar",
	minLen: 8,
	mime:   "", // dynamic: "ar archive" or "Debian binary package …"
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "!<arch>\n")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return doAr(file)
	},
}

var matcherRpm = fileMatcher{
	name:   "rpm",
	minLen: 96,
	mime:   "application/x-rpm",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 96 || !HasPrefix(b, "\xED\xAB\xEE\xDB") {
			return false
		}
		major := b[4]
		return major == 3 || major == 4
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "RPM package data"
	},
}

var matcherTar = fileMatcher{
	name:   "tar",
	minLen: 501,
	mime:   "", // dynamic: "Posix tar archive" or "VMware OVA appliance"
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 500 && Equal(b[257:262], "ustar")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return doTar(file)
	},
}

var matcherZip = fileMatcher{
	name:   "zip",
	minLen: 6,
	mime:   "", // dynamic: many sub-types (docx, apk, epub, etc.)
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 5 && HasPrefix(b, "PK\x03\x04")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return doZip(file)
	},
}

var matcherDmg = fileMatcher{
	name:   "dmg",
	minLen: 1,
	mime:   "application/x-apple-diskimage",
	match: func(b []byte, lenb int, magic int, file *os.File) bool {
		return hasDmgTrailer(file)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple UDIF disk image"
	},
}

var matcherEwf = fileMatcher{
	name:   "ewf",
	minLen: 8,
	mime:   "application/x-ewf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && (HasPrefix(b, "EVF\x09\x0D\x0A\xFF\x00") || HasPrefix(b, "LVF\x09\x0D\x0A\xFF\x00"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Expert Witness Compression Format (EWF) image"
	},
}

var matcherVmdk = fileMatcher{
	name:   "vmdk",
	minLen: 4,
	mime:   "application/x-vmdk",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "KDMV")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "VMware virtual disk"
	},
}

var matcherVmwareNvram = fileMatcher{
	name:   "vmware-nvram",
	minLen: 32,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return looksLikeVMwareNvram(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "VMware NVRAM file"
	},
}

var matcherQcow = fileMatcher{
	name:   "qcow",
	minLen: 4,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "QFI\xfb")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "QEMU QCOW disk image"
	},
}

func looksLikeVMwareNvram(b []byte) bool {
	if looksLikeVMwareNvramMRVN(b) {
		return true
	}
	return looksLikeVMwareNvramUEFI(b)
}

func looksLikeVMwareNvramUEFI(b []byte) bool {
	// VMware .nvram files commonly store a UEFI firmware volume header at byte 0.
	// EFI_FIRMWARE_VOLUME_HEADER signature "_FVH" sits at offset 0x28.
	if len(b) < 64 || !Equal(b[40:44], "_FVH") {
		return false
	}

	// UEFI firmware volume header starts with a 16-byte zero vector.
	for i := 0; i < 16; i++ {
		if b[i] != 0x00 {
			return false
		}
	}

	// Header length and revision sanity checks help reduce false positives.
	headerLen := peekLe(b[52:54], 2)
	if headerLen < 56 || headerLen > len(b) {
		return false
	}

	revision := b[55]
	return revision == 1 || revision == 2
}

func looksLikeVMwareNvramMRVN(b []byte) bool {
	// Legacy VMware NVRAM often starts with "MRVN" and then CMOS-tagged records.
	if len(b) < 32 || !HasPrefix(b, "MRVN") {
		return false
	}

	// Version field is usually a small LE integer (often 1).
	version := peekLe(b[4:8], 4)
	if version <= 0 || version > 16 {
		return false
	}

	end := len(b)
	if end > 512 {
		end = 512
	}

	// Require at least one CMOS marker near the header.
	return bytes.Contains(b[8:end], []byte("CMOS"))
}

var matcherVhdx = fileMatcher{
	name:   "vhdx",
	minLen: 8,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "vhdxfile")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft VHDX disk image"
	},
}

var matcherVdi = fileMatcher{
	name:   "vdi",
	minLen: len("<<< Oracle VM VirtualBox Disk Image >>>"),
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= len("<<< Oracle VM VirtualBox Disk Image >>>") &&
			HasPrefix(b, "<<< Oracle VM VirtualBox Disk Image >>>")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "VirtualBox VDI disk image"
	},
}

var matcherBzip2 = fileMatcher{
	name:   "bzip2",
	minLen: 5,
	mime:   "application/x-bzip2",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 4 && HasPrefix(b, "BZh")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "bzip2 compressed data"
	},
}

var matcherXz = fileMatcher{
	name:   "xz",
	minLen: 6,
	mime:   "application/x-xz",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 6 && HasPrefix(b, "\xFD7zXZ\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "XZ compressed data"
	},
}

var matcherZstd = fileMatcher{
	name:   "zstd",
	minLen: 4,
	mime:   "application/zstd",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x28\xB5\x2F\xFD")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Zstandard compressed data"
	},
}

var matcherLz4 = fileMatcher{
	name:   "lz4",
	minLen: 4,
	mime:   "application/x-lz4",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x04\x22\x4D\x18")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LZ4 compressed data"
	},
}

var matcherLzip = fileMatcher{
	name:   "lzip",
	minLen: 4,
	mime:   "application/x-lzip",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "LZIP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LZIP compressed data"
	},
}

var matcherGzip = fileMatcher{
	name:   "gzip",
	minLen: 11,
	mime:   "application/gzip",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 10 && HasPrefix(b, "\x1f\x8b")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "gzip compressed data"
	},
}

var matcherSzdd = fileMatcher{
	name:   "szdd",
	minLen: 8,
	mime:   "application/x-ms-compress",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "SZDD")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MS Compress archive data, SZDD variant"
	},
}

var matcherRar = fileMatcher{
	name:   "rar",
	minLen: 7,
	mime:   "application/vnd.rar",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return (lenb >= 8 && HasPrefix(b, "\x52\x61\x72\x21\x1A\x07\x01\x00")) ||
			(lenb >= 7 && HasPrefix(b, "\x52\x61\x72\x21\x1A\x07\x00"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "RAR archive data"
	},
}

var matcher7zip = fileMatcher{
	name:   "7zip",
	minLen: 17,
	mime:   "application/x-7z-compressed",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && HasPrefix(b, "\x37\x7A\xBC\xAF\x27\x1C")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "7zip archive data"
	},
}

var matcherCpio = fileMatcher{
	name:   "cpio",
	minLen: 6,
	mime:   "application/x-cpio",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb >= 6 && (HasPrefix(b, "070701") || HasPrefix(b, "070702") || HasPrefix(b, "070707")) {
			return true
		}
		return lenb >= 2 && (HasPrefix(b, "\xC7\x71") || HasPrefix(b, "\x71\xC7"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		switch {
		case HasPrefix(b, "070701"):
			return "CPIO archive (SVR4 no CRC)"
		case HasPrefix(b, "070702"):
			return "CPIO archive (SVR4 with CRC)"
		case HasPrefix(b, "070707"):
			return "CPIO archive (portable ASCII)"
		default:
			return "CPIO archive"
		}
	},
}

var matcherLzh = fileMatcher{
	name:   "lzh",
	minLen: 7,
	mime:   "application/x-lzh-compressed",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		// LHA/LZH header: [size][checksum]-lhX- where X is 0-9 or a-e
		return lenb >= 7 && b[2] == '-' && b[3] == 'l' && b[4] == 'h' && b[6] == '-'
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "LHa archive"
	},
}

var matcherSquashfs = fileMatcher{
	name:   "squashfs",
	minLen: 4,
	mime:   "application/x-squashfs",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && (HasPrefix(b, "sqsh") || HasPrefix(b, "hsqs") ||
			HasPrefix(b, "sqlz") || HasPrefix(b, "qshs"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Squashfs filesystem"
	},
}

var matcherZlib = fileMatcher{
	name:   "zlib",
	minLen: 2,
	mime:   "application/zlib",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		// First byte 0x78 = deflate with 32KB window; second byte must satisfy
		// (CMF*256 + FLG) % 31 == 0. Common values: 0x789C, 0x78DA, 0x7801, 0x785E.
		return lenb >= 2 && b[0] == 0x78 && (uint16(b[0])<<8+uint16(b[1]))%31 == 0
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "zlib compressed data"
	},
}

var matcherCab = fileMatcher{
	name:   "cab",
	minLen: 17,
	mime:   "application/vnd.ms-cab-compressed",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && HasPrefix(b, "\x4D\x53\x43\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Cabinet file"
	},
}
