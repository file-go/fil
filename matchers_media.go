package main

import (
	"bytes"
	"fmt"
	"os"
)

var matcherPng = fileMatcher{
	name:   "png",
	minLen: 29,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 28 && HasPrefix(b, "\x89PNG\x0d\x0a\x1a\x0a")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "PNG image data"
	},
}

var matcherGif = fileMatcher{
	name:   "gif",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && (HasPrefix(b, "GIF87a") || HasPrefix(b, "GIF89a"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "GIF image data"
	},
}

var matcherJpeg = fileMatcher{
	name:   "jpeg",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "\xff\xd8")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "JPEG / jpg image data"
	},
}

var matcherDds = fileMatcher{
	name:   "dds",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "DDS ")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "DDS image data"
	},
}

var matcherExr = fileMatcher{
	name:   "exr",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x76\x2F\x31\x01")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "OpenEXR image data"
	},
}

var matcherHdr = fileMatcher{
	name:   "hdr",
	minLen: 6,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 6 && (HasPrefix(b, "#?RADIANCE") || HasPrefix(b, "#?RGBE"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Radiance HDR image data"
	},
}

var matcherIcns = fileMatcher{
	name:   "icns",
	minLen: 8,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 8 && HasPrefix(b, "icns")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple icon image"
	},
}

var matcherTga = fileMatcher{
	name:   "tga",
	minLen: 18,
	match: func(b []byte, lenb int, magic int) bool {
		footer := []byte("TRUEVISION-XFILE.\x00")
		if lenb >= 26 && bytes.HasSuffix(b, footer) {
			return true
		}
		tail, ok := readTail(18)
		return ok && bytes.Equal(tail, footer)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Targa image data"
	},
}

var matcherCr2 = fileMatcher{
	name:   "cr2",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 12 && isTiffLike(b) && Equal(b[8:10], "CR")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Canon CR2 raw image data"
	},
}

var matcherNef = fileMatcher{
	name:   "nef",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isTiffLike(b) && sampleContains(b, "Nikon", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Nikon NEF raw image data"
	},
}

var matcherArw = fileMatcher{
	name:   "arw",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isTiffLike(b) && sampleContains(b, "SONY", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Sony ARW raw image data"
	},
}

var matcherRaf = fileMatcher{
	name:   "raf",
	minLen: 15,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 15 && HasPrefix(b, "FUJIFILMCCD-RAW")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Fuji RAF raw image data"
	},
}

var matcherOrf = fileMatcher{
	name:   "orf",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && (HasPrefix(b, "\x49\x49\x52\x4F") || HasPrefix(b, "\x4D\x4D\x4F\x52"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Olympus ORF raw image data"
	},
}

var matcherRw2 = fileMatcher{
	name:   "rw2",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && (HasPrefix(b, "\x49\x49\x55\x00") || HasPrefix(b, "\x4D\x4D\x00\x55"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Panasonic RW2 raw image data"
	},
}

var matcherDng = fileMatcher{
	name:   "dng",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isTiffLike(b) && sampleContains(b, "DNGVersion", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Adobe DNG raw image data"
	},
}

var matcherCr3 = fileMatcher{
	name:   "cr3",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isCr3Like(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Canon CR3 raw image data"
	},
}

var matcherFlv = fileMatcher{
	name:   "flv",
	minLen: 3,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 3 && HasPrefix(b, "FLV")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "FLV video file"
	},
}

var matcherMatroska = fileMatcher{
	name:   "matroska",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("matroska"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Matroska video file"
	},
}

var matcherWebm = fileMatcher{
	name:   "webm",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("webm"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WebM video file"
	},
}

var matcherOgg = fileMatcher{
	name:   "ogg",
	minLen: 37,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 36 && HasPrefix(b, "OggS\x00\x02")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return oggSubtype(b)
	},
}

var matcherWav = fileMatcher{
	name:   "wav",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:16], "WAVEfmt ")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WAV audio"
	},
}

var matcherMp3 = fileMatcher{
	name:   "mp3",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 &&
			(HasPrefix(b, "ID3") || HasPrefix(b, "\xff\xfb") || HasPrefix(b, "\xff\xf3") || HasPrefix(b, "\xff\xf2"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MP3 audio file"
	},
}

var matcherHeif = fileMatcher{
	name:   "heif",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isHeifFamily(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "HEIF image"
	},
}

var matcherAvif = fileMatcher{
	name:   "avif",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isAvifLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AVIF image"
	},
}

var matcherJxl = fileMatcher{
	name:   "jxl",
	minLen: 2,
	match: func(b []byte, lenb int, magic int) bool {
		// JPEG XL codestream signature.
		if lenb >= 2 && HasPrefix(b, "\xFF\x0A") {
			return true
		}
		// JPEG XL container signature.
		return lenb >= 12 && HasPrefix(b, "\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "JPEG XL image data"
	},
}

var matcherJpeg2000 = fileMatcher{
	name:   "jpeg2000",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		// JPEG 2000 codestream signature.
		if lenb >= 4 && HasPrefix(b, "\xFF\x4F\xFF\x51") {
			return true
		}
		// JP2 signature box.
		return lenb >= 12 && HasPrefix(b, "\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "JPEG 2000 image data"
	},
}

var matcherM4a = fileMatcher{
	name:   "m4a",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isM4aLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "M4A audio"
	},
}

var matcherQuickTime = fileMatcher{
	name:   "quicktime",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isQuickTimeLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "QuickTime movie file"
	},
}

var matcher3gpp = fileMatcher{
	name:   "3gpp",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return is3gpLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		if hasFtypBrand(b, "3g2") {
			return "3GPP2 video file"
		}
		return "3GPP video file"
	},
}

var matcherM4v = fileMatcher{
	name:   "m4v",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isM4vLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "M4V video file"
	},
}

var matcherMp4 = fileMatcher{
	name:   "mp4",
	minLen: 12,
	match: func(b []byte, lenb int, magic int) bool {
		return isMp4Like(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MP4 video file"
	},
}

var matcherMpegPs = fileMatcher{
	name:   "mpeg-ps",
	minLen: 4,
	match: func(b []byte, lenb int, magic int) bool {
		// MPEG Program Stream pack header (commonly .mpg/.mpeg/.vob).
		return lenb >= 4 && HasPrefix(b, "\x00\x00\x01\xBA")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MPEG video file"
	},
}

var matcherMpegTs = fileMatcher{
	name:   "mpeg-ts",
	minLen: 377,
	match: func(b []byte, lenb int, magic int) bool {
		return isMpegTsLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MPEG-TS video file"
	},
}

var matcherIco = fileMatcher{
	name:   "ico",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x00\x00\x01\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MS Windows icon resource"
	},
}

var matcherFlac = fileMatcher{
	name:   "flac",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x66\x4C\x61\x43")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "FLAC audio format"
	},
}

var matcherMidi = fileMatcher{
	name:   "midi",
	minLen: 14,
	match: func(b []byte, lenb int, magic int) bool {
		if lenb < 14 || !HasPrefix(b, "MThd") {
			return false
		}
		headerLen := peekBe(b[4:], 4)
		if headerLen != 6 {
			return false
		}
		format := peekBe(b[8:], 2)
		tracks := peekBe(b[10:], 2)
		return format >= 0 && format <= 2 && tracks > 0
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		format := peekBe(b[8:], 2)
		tracks := peekBe(b[10:], 2)
		division := peekBe(b[12:], 2)

		trackWord := "track"
		if tracks != 1 {
			trackWord = "tracks"
		}

		if division&0x8000 == 0 {
			return fmt.Sprintf("Standard MIDI data (format %d) using %d %s at 1/%d", format, tracks, trackWord, division)
		}

		fps := 256 - ((division >> 8) & 0xFF)
		ticksPerFrame := division & 0xFF
		return fmt.Sprintf("Standard MIDI data (format %d) using %d %s at %d fps, %d ticks/frame", format, tracks, trackWord, fps, ticksPerFrame)
	},
}

var matcherPsd = fileMatcher{
	name:   "psd",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 && HasPrefix(b, "\x38\x42\x50\x53")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Photoshop document"
	},
}

var matcherAvi = fileMatcher{
	name:   "avi",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:11], "AVI")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AVI file"
	},
}

var matcherAsf = fileMatcher{
	name:   "asf",
	minLen: 16,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb >= 16 && HasPrefix(b, "\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ASF media file"
	},
}

var matcherWebp = fileMatcher{
	name:   "webp",
	minLen: 33,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:12], "WEBP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Google Webp file"
	},
}
