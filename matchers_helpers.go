package main

import "bytes"

func readTail(n int) ([]byte, bool) {
	if activeFile == nil || n <= 0 {
		return nil, false
	}
	info, err := activeFile.Stat()
	if err != nil {
		return nil, false
	}
	if info.Size() < int64(n) {
		return nil, false
	}
	buf := make([]byte, n)
	_, err = activeFile.ReadAt(buf, info.Size()-int64(n))
	if err != nil {
		return nil, false
	}
	return buf, true
}

func hasDmgTrailer() bool {
	buf, ok := readTail(512)
	if !ok {
		return false
	}
	return bytes.HasPrefix(buf, []byte("koly"))
}

func hasParquetFooter() bool {
	buf, ok := readTail(4)
	if !ok {
		return false
	}
	return bytes.Equal(buf, []byte("PAR1"))
}

func hasArrowFooter() bool {
	buf, ok := readTail(6)
	if !ok {
		return false
	}
	return bytes.Equal(buf, []byte("ARROW1"))
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

func isHeifFamily(b []byte) bool {
	return hasFtypBrand(b, "heic", "heix", "hevc", "mif1")
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
