package main

import "os"

var matcherParquet = fileMatcher{
	name:   "parquet",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "PAR1")
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
