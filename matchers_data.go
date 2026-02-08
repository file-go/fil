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
