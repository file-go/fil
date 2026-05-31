package main

import (
	"bytes"
	"os"
)

func readTail(file *os.File, n int) ([]byte, bool) {
	if file == nil || n <= 0 {
		return nil, false
	}
	info, err := file.Stat()
	if err != nil {
		return nil, false
	}
	if info.Size() < int64(n) {
		return nil, false
	}
	buf := make([]byte, n)
	_, err = file.ReadAt(buf, info.Size()-int64(n))
	if err != nil {
		return nil, false
	}
	return buf, true
}

func hasDmgTrailer(file *os.File) bool {
	buf, ok := readTail(file, 512)
	if !ok {
		return false
	}
	return bytes.HasPrefix(buf, []byte("koly"))
}

func hasParquetFooter(file *os.File) bool {
	buf, ok := readTail(file, 4)
	if !ok {
		return false
	}
	return bytes.Equal(buf, []byte("PAR1"))
}

func hasArrowFooter(file *os.File) bool {
	buf, ok := readTail(file, 6)
	if !ok {
		return false
	}
	return bytes.Equal(buf, []byte("ARROW1"))
}

// parse80BitExtended converts an 80-bit IEEE 754 extended-precision float (used
// by AIFF COMM chunk for sample rate) to an integer without importing math.
// Works correctly for all standard audio sample rates.
func parse80BitExtended(b []byte) int {
	if len(b) < 10 {
		return 0
	}
	exponent := int((uint16(b[0]&0x7F) << 8) | uint16(b[1]))
	mantissa := uint64(b[2])<<56 | uint64(b[3])<<48 | uint64(b[4])<<40 |
		uint64(b[5])<<32 | uint64(b[6])<<24 | uint64(b[7])<<16 |
		uint64(b[8])<<8 | uint64(b[9])
	if exponent == 0 || mantissa == 0 {
		return 0
	}
	shift := 16383 + 63 - exponent
	if shift < 0 || shift > 63 {
		return 0
	}
	return int(mantissa >> uint(shift))
}

func isTiffLike(b []byte) bool {
	return len(b) >= 4 && (bytes.HasPrefix(b, []byte{0x49, 0x49, 0x2A, 0x00}) || bytes.HasPrefix(b, []byte{0x4D, 0x4D, 0x00, 0x2A}))
}

func sampleContains(b []byte, needle string, max int) bool {
	end := len(b)
	if end > max {
		end = max
	}
	return bytes.Contains(b[:end], []byte(needle))
}

func sampleContainsASCIIOrUTF16LE(b []byte, needle string, max int) bool {
	end := len(b)
	if end > max {
		end = max
	}
	h := b[:end]
	if bytes.Contains(h, []byte(needle)) {
		return true
	}
	return bytes.Contains(h, asciiToUTF16LE(needle))
}

func asciiToUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		out[i*2] = s[i]
		out[i*2+1] = 0x00
	}
	return out
}

func hasFtypBrand(b []byte, brands ...string) bool {
	if len(b) < 12 {
		return false
	}
	if !bytes.Equal(b[4:8], []byte("ftyp")) {
		return false
	}
	end := len(b)
	if end > 64 {
		end = 64
	}
	h := b[8:end]
	for _, br := range brands {
		if bytes.Contains(h, []byte(br)) {
			return true
		}
	}
	return false
}

func hasFtypBoxPrefix(b []byte) bool {
	return len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp"))
}

func isHeifFamily(b []byte) bool {
	// AVIF can also carry the "mif1" compatible brand, so exclude it here.
	if isAvifLike(b) {
		return false
	}
	return hasFtypBrand(b, "heic", "heix", "hevc", "mif1")
}

func isAvifLike(b []byte) bool {
	return hasFtypBrand(b, "avif", "avis")
}

func isM4aLike(b []byte) bool {
	if hasFtypBrand(b, "M4A ") {
		return true
	}
	if hasFtypBrand(b, "isom", "mp42", "mp41") {
		end := len(b)
		if end > 4096 {
			end = 4096
		}
		if bytes.Contains(b[:end], []byte("mp4a")) {
			return true
		}
	}
	return false
}

func isQuickTimeLike(b []byte) bool {
	return hasFtypBrand(b, "qt  ")
}

func is3gpLike(b []byte) bool {
	return hasFtypBrand(b, "3gp", "3g2")
}

func isM4vLike(b []byte) bool {
	return hasFtypBrand(b, "M4V ")
}

func isCr3Like(b []byte) bool {
	return hasFtypBrand(b, "crx ")
}

func isMp4Like(b []byte) bool {
	if !hasFtypBoxPrefix(b) {
		return false
	}
	if isHeifFamily(b) || isM4aLike(b) || isQuickTimeLike(b) || is3gpLike(b) || isM4vLike(b) || isCr3Like(b) {
		return false
	}
	return true
}

func isMpegTsLike(b []byte) bool {
	// Standard TS (188-byte packets) and Blu-ray M2TS (192-byte packets).
	if len(b) >= 377 && b[0] == 0x47 && b[188] == 0x47 && b[376] == 0x47 {
		return true
	}
	return len(b) >= 389 && b[4] == 0x47 && b[196] == 0x47 && b[388] == 0x47
}

func oggSubtype(b []byte) string {
	end := len(b)
	if end > 4096 {
		end = 4096
	}
	h := b[:end]
	switch {
	case bytes.Contains(h, []byte("OpusHead")):
		return "Ogg Opus audio"
	case bytes.Contains(h, []byte("vorbis")):
		return "Ogg Vorbis audio"
	case bytes.Contains(h, []byte("fLaC")):
		return "Ogg FLAC audio"
	default:
		return "Ogg data"
	}
}

func looksLikeMsi(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	if !HasPrefix(b, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
		return false
	}
	if !bytes.Equal(b[8:24], make([]byte, 16)) {
		return false
	}
	end := len(b)
	if end > 8192 {
		end = 8192
	}
	h := b[:end]
	if bytes.Contains(h, []byte("MsiDatabase")) ||
		bytes.Contains(h, []byte("_StringData")) ||
		bytes.Contains(h, []byte("_StringPool")) ||
		bytes.Contains(h, []byte("MsiDigitalSignature")) {
		return true
	}
	return false
}
