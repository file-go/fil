package main

import (
	"bytes"
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
		return "Ogg data"
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

var matcherMp4 = fileMatcher{
	name:   "mp4",
	minLen: 17,
	match: func(b []byte, lenb int, magic int) bool {
		return lenb > 16 &&
			(HasPrefix(b, "\x00\x00\x00\x20\x66\x74\x79\x70") || HasPrefix(b, "\x00\x00\x00\x18\x66\x74\x79\x70") || HasPrefix(b, "\x00\x00\x00\x14\x66\x74\x79\x70"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MP4 video file"
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
