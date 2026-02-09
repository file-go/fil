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
