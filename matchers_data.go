package main

import (
	"bytes"
	"encoding/binary"
	"os"
)

var matcherParquet = fileMatcher{
	name:   "parquet",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "PAR1") && hasParquetFooter()
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Parquet data"
	},
}

var matcherAvro = fileMatcher{
	name:   "avro",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "Obj\x01")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Avro data"
	},
}

var matcherHdf5 = fileMatcher{
	name:   "hdf5",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "\x89HDF\x0d\x0a\x1a\x0a")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Hierarchical Data Format (version 5) data"
	},
}

var matcherNetcdf = fileMatcher{
	name:   "netcdf",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && (HasPrefix(b, "CDF\x01") || HasPrefix(b, "CDF\x02"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "NetCDF Data Format data"
	},
}

var matcherFeather = fileMatcher{
	name:   "feather",
	minLen: 6,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 6 && HasPrefix(b, "ARROW1") && hasArrowFooter()
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apache Arrow Feather"
	},
}

var matcherPgCustomDump = fileMatcher{
	name:   "pg-custom-dump",
	minLen: 5,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 5 && HasPrefix(b, "PGDMP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PostgreSQL custom database dump"
	},
}

var matcherRedisRdb = fileMatcher{
	name:   "redis-rdb",
	minLen: 9,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 9 || !HasPrefix(b, "REDIS") {
			return false
		}
		for i := 5; i < 9; i++ {
			if b[i] < '0' || b[i] > '9' {
				return false
			}
		}
		return true
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Redis database dump"
	},
}

var matcherDbf = fileMatcher{
	name:   "dbf",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 33 {
			return false
		}
		switch b[0] {
		case 0x02, 0x03, 0x04, 0x05, 0x30, 0x31, 0x32, 0x43, 0x63, 0x83, 0x8B, 0xCB, 0xF5:
		default:
			return false
		}
		month := b[2]
		day := b[3]
		if month < 1 || month > 12 || day < 1 || day > 31 {
			return false
		}
		headerLen := peekLe(b[8:], 2)
		recordLen := peekLe(b[10:], 2)
		if headerLen < 33 || recordLen <= 0 {
			return false
		}
		if headerLen%32 != 1 {
			return false
		}
		if headerLen <= lenb && b[headerLen-1] != 0x0D {
			return false
		}
		return true
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "dBase DBF database"
	},
}

var matcherOutlookStore = fileMatcher{
	name:   "outlook-store",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 12 || !HasPrefix(b, "!BDN") {
			return false
		}
		if !Equal(b[8:10], "SM") {
			return false
		}
		ver := peekLe(b[10:], 2)
		return ver == 14 || ver == 15 || ver == 23
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		ver := peekLe(b[10:], 2)
		if ver == 23 {
			return "Microsoft Outlook PST/OST message store (Unicode)"
		}
		return "Microsoft Outlook PST/OST message store (ANSI)"
	},
}

var matcherSqlite = fileMatcher{
	name:   "sqlite",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "SQLite database"
	},
}

var matcherSqliteWal = fileMatcher{
	name:   "sqlite-wal",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && (Equal(b[:4], "\x37\x7F\x06\x82") || Equal(b[:4], "\x37\x7F\x06\x83"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "SQLite WAL file"
	},
}

var matcherSqliteJournal = fileMatcher{
	name:   "sqlite-journal",
	minLen: 16,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb <= 15 || !HasPrefix(b, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00") {
			return false
		}
		end := lenb
		if end > 4096 {
			end = 4096
		}
		return bytes.Contains(b[:end], []byte("journal"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "SQLite journal file"
	},
}

var matcherPcapng = fileMatcher{
	name:   "pcapng",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x0A\x0D\x0D\x0A")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PCAP-ng capture file"
	},
}

var matcherPcap = fileMatcher{
	name:   "pcap",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 &&
			(HasPrefix(b, "\xD4\xC3\xB2\xA1") || HasPrefix(b, "\xA1\xB2\xC3\xD4") || HasPrefix(b, "\x4D\x3C\xB2\xA1") || HasPrefix(b, "\xA1\xB2\x3C\x4D"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PCAP capture file"
	},
}

var matcherTNEF = fileMatcher{
	name:   "tnef",
	minLen: 6,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 6 && HasPrefix(b, "\x78\x9F\x3E\x22")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "TNEF attachment data"
	},
}

var matcherGettextMO = fileMatcher{
	name:   "gettext-mo",
	minLen: 28,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 28 {
			return false
		}
		// GNU gettext MO magic (little-endian and big-endian encodings).
		if !(HasPrefix(b, "\xDE\x12\x04\x95") || HasPrefix(b, "\x95\x04\x12\xDE")) {
			return false
		}
		// Revision is typically 0.0 or 1.0.
		revision := peekLe(b[4:], 4)
		if HasPrefix(b, "\x95\x04\x12\xDE") {
			revision = peekBe(b[4:], 4)
		}
		return revision == 0 || revision == 1
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "GNU gettext message catalog"
	},
}

var matcherGIRTypelib = fileMatcher{
	name:   "gir-typelib",
	minLen: len("GOBJ\nMETADATA\r\n\x1A"),
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= len("GOBJ\nMETADATA\r\n\x1A") && HasPrefix(b, "GOBJ\nMETADATA\r\n\x1A")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "G-IR binary database"
	},
}

var matcherCrx = fileMatcher{
	name:   "crx",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 12 || !HasPrefix(b, "Cr24") {
			return false
		}
		v := peekLe(b[4:], 4)
		return v == 2 || v == 3
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Google Chrome extension"
	},
}

var matcherRcc = fileMatcher{
	name:   "rcc",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "qres")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Qt Binary Resource file"
	},
}

var matcherLnk = fileMatcher{
	name:   "lnk",
	minLen: 20,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 20 && HasPrefix(b, "\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows shortcut"
	},
}

var matcherChm = fileMatcher{
	name:   "chm",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "ITSF")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MS Windows HtmlHelp Data"
	},
}

var matcherRegistryHive = fileMatcher{
	name:   "registry-hive",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "regf")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows Registry hive"
	},
}

var matcherPrefetch = fileMatcher{
	name:   "prefetch",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 8 || !Equal(b[4:8], "SCCA") {
			return false
		}
		version := peekLe(b[:4], 4)
		return version == 0x11 || version == 0x17 || version == 0x1a || version == 0x1e
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows Prefetch file"
	},
}

var matcherEvtx = fileMatcher{
	name:   "evtx",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "ElfFile\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows Event Log"
	},
}

var matcherPdb = fileMatcher{
	name:   "pdb",
	minLen: len("Microsoft C/C++ MSF 7.00"),
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= len("Microsoft C/C++ MSF 7.00") &&
			HasPrefix(b, "Microsoft C/C++ MSF 7.00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Program Database"
	},
}

var matcherRoslynPdb = fileMatcher{
	name:   "roslyn-pdb",
	minLen: 32,
	match: func(b []byte, lenb int, magic int) bool {
		// Portable PDB files are ECMA-335 metadata blobs with "BSJB" signature.
		if lenb < 32 || !HasPrefix(b, "BSJB") {
			return false
		}
		// Version string commonly includes "PDB v1.0".
		end := lenb
		if end > 128 {
			end = 128
		}
		return bytes.Contains(bytes.ToLower(b[:end]), []byte("pdb v1.0"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Microsoft Roslyn C# debugging symbols version 1.0"
	},
}

var matcherMagicMgc = fileMatcher{
	name:   "magic-mgc",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		// libmagic compiled magic header (endianness variants).
		return lenb >= 4 && (HasPrefix(b, "\x1C\x04\x1E\xF1") || HasPrefix(b, "\xF1\x1E\x04\x1C"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "magic binary file for file(1) cmd"
	},
}

var matcherMinidump = fileMatcher{
	name:   "minidump",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "MDMP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows minidump"
	},
}

var matcherThumbcache = fileMatcher{
	name:   "thumbcache",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "CMMM")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows thumbnail cache"
	},
}

var matcherRecycleBinI = fileMatcher{
	name:   "recyclebin-i",
	minLen: 24,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 24 {
			return false
		}
		ver := binary.LittleEndian.Uint64(b[:8])
		if ver != 1 && ver != 2 {
			return false
		}

		// Deletion timestamp as FILETIME.
		t := binary.LittleEndian.Uint64(b[16:24])
		const minFiletime = uint64(116444736000000000) // 1970-01-01 UTC
		const maxReasonableFiletime = uint64(600000000000000000)
		if t < minFiletime || t > maxReasonableFiletime {
			return false
		}

		return hasRecycleBinPathHint(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Windows Recycle Bin metadata"
	},
}

func hasRecycleBinPathHint(b []byte) bool {
	if len(b) <= 24 {
		return false
	}
	end := len(b)
	if end > 256 {
		end = 256
	}
	s := b[24:end]
	return bytes.Contains(s, []byte{0x3a, 0x00, 0x5c, 0x00}) || bytes.Contains(s, []byte{0x5c, 0x00, 0x5c, 0x00})
}

var matcherTdf = fileMatcher{
	name:   "tdf",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x54\x44\x46\x24")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Telegram Desktop file"
	},
}

var matcherTdef = fileMatcher{
	name:   "tdef",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x54\x44\x45\x46")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Telegram Desktop encrypted file"
	},
}
