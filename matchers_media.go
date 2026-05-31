package main

import (
	"bytes"
	"fmt"
	"os"
)

var matcherPng = fileMatcher{
	name:   "png",
	minLen: 29,
	mime:   "image/png",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 28 && HasPrefix(b, "\x89PNG\x0d\x0a\x1a\x0a")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describePNG(b)
	},
}

func describePNG(b []byte) string {
	if len(b) < 29 {
		return "PNG image data"
	}
	width := peekBe(b[16:], 4)
	height := peekBe(b[20:], 4)
	if width <= 0 || height <= 0 {
		return "PNG image data"
	}
	bitDepth := int(b[24])
	colorType := int(b[25])
	interlaceStr := "non-interlaced"
	if b[28] == 1 {
		interlaceStr = "interlaced"
	}
	colorName := map[int]string{
		0: "grayscale", 2: "RGB", 3: "colormap",
		4: "grayscale, alpha", 6: "RGBA",
	}[colorType]
	if colorName == "" {
		colorName = "unknown"
	}
	return fmt.Sprintf("PNG image data, %d x %d, %d-bit/color %s, %s",
		width, height, bitDepth, colorName, interlaceStr)
}

var matcherGif = fileMatcher{
	name:   "gif",
	minLen: 17,
	mime:   "image/gif",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && (HasPrefix(b, "GIF87a") || HasPrefix(b, "GIF89a"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeGIF(b)
	},
}

func describeGIF(b []byte) string {
	if len(b) < 10 {
		return "GIF image data"
	}
	version := string(b[3:6])
	width := peekLe(b[6:], 2)
	height := peekLe(b[8:], 2)
	if width > 0 && height > 0 {
		return fmt.Sprintf("GIF image data, version %s, %d x %d", version, width, height)
	}
	return fmt.Sprintf("GIF image data, version %s", version)
}

var matcherJpeg = fileMatcher{
	name:   "jpeg",
	minLen: 33,
	mime:   "image/jpeg",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 32 && HasPrefix(b, "\xff\xd8")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeJPEG(b)
	},
}

func describeJPEG(b []byte) string {
	// Scan JPEG markers starting after SOI to find a Start-of-Frame marker.
	offset := 2
	for offset+3 < len(b) {
		if b[offset] != 0xFF {
			break
		}
		marker := b[offset+1]
		// SOF markers: 0xC0–0xCF excluding DHT(C4), JPG(C8), DAC(CC).
		isSof := marker >= 0xC0 && marker <= 0xCF &&
			marker != 0xC4 && marker != 0xC8 && marker != 0xCC
		if isSof && offset+9 < len(b) {
			height := peekBe(b[offset+5:], 2)
			width := peekBe(b[offset+7:], 2)
			if width > 0 && height > 0 {
				if marker == 0xC2 {
					return fmt.Sprintf("JPEG / jpg image data, %d x %d, progressive", width, height)
				}
				return fmt.Sprintf("JPEG / jpg image data, %d x %d", width, height)
			}
			break
		}
		// Standalone markers with no length field.
		if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) {
			offset += 2
			continue
		}
		if offset+3 >= len(b) {
			break
		}
		segLen := peekBe(b[offset+2:], 2)
		if segLen < 2 {
			break
		}
		offset += 2 + segLen
	}
	return "JPEG / jpg image data"
}

var matcherDds = fileMatcher{
	name:   "dds",
	minLen: 4,
	mime:   "image/vnd-ms.dds",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "DDS ")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "DDS image data"
	},
}

var matcherExr = fileMatcher{
	name:   "exr",
	minLen: 4,
	mime:   "image/x-exr",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x76\x2F\x31\x01")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "OpenEXR image data"
	},
}

var matcherHdr = fileMatcher{
	name:   "hdr",
	minLen: 6,
	mime:   "image/vnd.radiance",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 6 && (HasPrefix(b, "#?RADIANCE") || HasPrefix(b, "#?RGBE"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Radiance HDR image data"
	},
}

var matcherIcns = fileMatcher{
	name:   "icns",
	minLen: 8,
	mime:   "image/icns",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 8 && HasPrefix(b, "icns")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Apple icon image"
	},
}

var matcherTga = fileMatcher{
	name:   "tga",
	minLen: 18,
	mime:   "image/x-tga",
	match: func(b []byte, lenb int, magic int, file *os.File) bool {
		footer := []byte("TRUEVISION-XFILE.\x00")
		if lenb >= 26 && bytes.HasSuffix(b, footer) {
			return true
		}
		tail, ok := readTail(file, 18)
		return ok && bytes.Equal(tail, footer)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Targa image data"
	},
}

var matcherCr2 = fileMatcher{
	name:   "cr2",
	minLen: 12,
	mime:   "image/x-canon-cr2",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 12 && isTiffLike(b) && Equal(b[8:10], "CR")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Canon CR2 raw image data"
	},
}

var matcherNef = fileMatcher{
	name:   "nef",
	minLen: 12,
	mime:   "image/x-nikon-nef",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isTiffLike(b) && sampleContains(b, "Nikon", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Nikon NEF raw image data"
	},
}

var matcherArw = fileMatcher{
	name:   "arw",
	minLen: 12,
	mime:   "image/x-sony-arw",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isTiffLike(b) && sampleContains(b, "SONY", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Sony ARW raw image data"
	},
}

var matcherRaf = fileMatcher{
	name:   "raf",
	minLen: 15,
	mime:   "image/x-fuji-raf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 15 && HasPrefix(b, "FUJIFILMCCD-RAW")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Fuji RAF raw image data"
	},
}

var matcherOrf = fileMatcher{
	name:   "orf",
	minLen: 4,
	mime:   "image/x-olympus-orf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && (HasPrefix(b, "\x49\x49\x52\x4F") || HasPrefix(b, "\x4D\x4D\x4F\x52"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Olympus ORF raw image data"
	},
}

var matcherRw2 = fileMatcher{
	name:   "rw2",
	minLen: 4,
	mime:   "image/x-panasonic-rw2",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && (HasPrefix(b, "\x49\x49\x55\x00") || HasPrefix(b, "\x4D\x4D\x00\x55"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Panasonic RW2 raw image data"
	},
}

var matcherDng = fileMatcher{
	name:   "dng",
	minLen: 12,
	mime:   "image/x-adobe-dng",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isTiffLike(b) && sampleContains(b, "DNGVersion", 8192)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Adobe DNG raw image data"
	},
}

var matcherCr3 = fileMatcher{
	name:   "cr3",
	minLen: 12,
	mime:   "image/x-canon-cr3",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isCr3Like(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Canon CR3 raw image data"
	},
}

var matcherFlv = fileMatcher{
	name:   "flv",
	minLen: 3,
	mime:   "video/x-flv",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 3 && HasPrefix(b, "FLV")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "FLV video file"
	},
}

var matcherMatroska = fileMatcher{
	name:   "matroska",
	minLen: 4,
	mime:   "video/x-matroska",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("matroska"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Matroska video file"
	},
}

var matcherWebm = fileMatcher{
	name:   "webm",
	minLen: 4,
	mime:   "video/webm",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("webm"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "WebM video file"
	},
}

var matcherOgg = fileMatcher{
	name:   "ogg",
	minLen: 37,
	mime:   "audio/ogg",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 36 && HasPrefix(b, "OggS\x00\x02")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return oggSubtype(b)
	},
}

var matcherAiff = fileMatcher{
	name:   "aiff",
	minLen: 12,
	mime:   "audio/aiff",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 12 && HasPrefix(b, "FORM") &&
			(Equal(b[8:12], "AIFF") || Equal(b[8:12], "AIFC"))
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeAIFF(b)
	},
}

func describeAIFF(b []byte) string {
	isAIFC := len(b) >= 12 && Equal(b[8:12], "AIFC")
	base := "AIFF audio data"
	if isAIFC {
		base = "AIFF-C audio data"
	}
	// COMM chunk is typically first, starting at byte 12:
	// "COMM"(4) + size(4) + channels(2) + frames(4) + sampleSize(2) + sampleRate(10)
	if len(b) >= 38 && Equal(b[12:16], "COMM") {
		channels := peekBe(b[20:], 2)
		sampleSize := peekBe(b[26:], 2)
		sampleRate := parse80BitExtended(b[28:])
		if sampleRate > 0 && channels > 0 && sampleSize > 0 {
			chStr := map[int]string{1: "mono", 2: "stereo"}[channels]
			if chStr == "" {
				chStr = fmt.Sprintf("%d channels", channels)
			}
			return fmt.Sprintf("%s, %d Hz, %s, %d-bit", base, sampleRate, chStr, sampleSize)
		}
	}
	return base
}

var matcherAac = fileMatcher{
	name:   "aac",
	minLen: 2,
	mime:   "audio/aac",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		if lenb < 2 {
			return false
		}
		// ADTS sync word: 0xFF followed by 0xF0 or 0xF1 (MPEG-4 AAC) or 0xF8/0xF9 (MPEG-2 AAC).
		if b[0] != 0xFF {
			return false
		}
		return b[1] == 0xF1 || b[1] == 0xF9
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AAC audio data"
	},
}

var matcherWav = fileMatcher{
	name:   "wav",
	minLen: 33,
	mime:   "audio/wav",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:16], "WAVEfmt ")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeWAV(b)
	},
}

func describeWAV(b []byte) string {
	if len(b) < 36 {
		return "WAV audio"
	}
	audioFmt := peekLe(b[20:], 2)
	channels := peekLe(b[22:], 2)
	sampleRate := peekLe(b[24:], 4)
	bitsPerSample := peekLe(b[34:], 2)
	if sampleRate <= 0 || channels <= 0 || bitsPerSample <= 0 {
		return "WAV audio"
	}
	fmtName := map[int]string{
		1: "PCM", 3: "IEEE float", 6: "a-law", 7: "mu-law", 0xFFFE: "extensible",
	}[audioFmt]
	if fmtName == "" {
		fmtName = fmt.Sprintf("format 0x%04X", audioFmt)
	}
	chStr := map[int]string{1: "mono", 2: "stereo"}[channels]
	if chStr == "" {
		chStr = fmt.Sprintf("%d channels", channels)
	}
	return fmt.Sprintf("WAV audio, %d Hz, %s, %d-bit %s", sampleRate, chStr, bitsPerSample, fmtName)
}

var matcherMp3 = fileMatcher{
	name:   "mp3",
	minLen: 17,
	mime:   "audio/mpeg",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "image/heif",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isHeifFamily(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "HEIF image"
	},
}

var matcherAvif = fileMatcher{
	name:   "avif",
	minLen: 12,
	mime:   "image/avif",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isAvifLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AVIF image"
	},
}

var matcherJxl = fileMatcher{
	name:   "jxl",
	minLen: 2,
	mime:   "image/jxl",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "image/jp2",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "audio/mp4",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isM4aLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "M4A audio"
	},
}

var matcherQuickTime = fileMatcher{
	name:   "quicktime",
	minLen: 12,
	mime:   "video/quicktime",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isQuickTimeLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "QuickTime movie file"
	},
}

var matcher3gpp = fileMatcher{
	name:   "3gpp",
	minLen: 12,
	mime:   "", // dynamic: "video/3gpp" or "video/3gpp2"
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "video/x-m4v",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isM4vLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "M4V video file"
	},
}

var matcherMp4 = fileMatcher{
	name:   "mp4",
	minLen: 12,
	mime:   "video/mp4",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isMp4Like(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MP4 video file"
	},
}

var matcherMpegPs = fileMatcher{
	name:   "mpeg-ps",
	minLen: 4,
	mime:   "video/mpeg",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "video/mp2t",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isMpegTsLike(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MPEG-TS video file"
	},
}

var matcherIco = fileMatcher{
	name:   "ico",
	minLen: 17,
	mime:   "image/x-icon",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && HasPrefix(b, "\x00\x00\x01\x00")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MS Windows icon resource"
	},
}

var matcherCur = fileMatcher{
	name:   "cur",
	minLen: 6,
	mime:   "image/x-icon",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 6 && HasPrefix(b, "\x00\x00\x02\x00") && peekLe(b[4:], 2) > 0
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "MS Windows cursor resource"
	},
}

var matcherFlac = fileMatcher{
	name:   "flac",
	minLen: 17,
	mime:   "audio/flac",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && HasPrefix(b, "\x66\x4C\x61\x43")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeFLAC(b)
	},
}

func describeFLAC(b []byte) string {
	// STREAMINFO metadata block starts at byte 4 (after "fLaC" marker).
	// Byte 4: last-block flag (1 bit) + block type (7 bits); STREAMINFO = type 0.
	// Bytes 5-7: block length. STREAMINFO data starts at byte 8.
	// Sample rate: 20 bits starting at STREAMINFO byte 10 (file byte 18).
	// Channels-1: 3 bits; bits_per_sample-1: 5 bits — packed in file bytes 20-21.
	if len(b) < 22 {
		return "FLAC audio format"
	}
	sampleRate := (int(b[18]) << 12) | (int(b[19]) << 4) | (int(b[20]) >> 4)
	channels := ((int(b[20]) >> 1) & 0x07) + 1
	bitsPerSample := ((int(b[20])&0x01)<<4 | int(b[21])>>4) + 1
	if sampleRate <= 0 {
		return "FLAC audio format"
	}
	chStr := map[int]string{1: "mono", 2: "stereo"}[channels]
	if chStr == "" {
		chStr = fmt.Sprintf("%d channels", channels)
	}
	return fmt.Sprintf("FLAC audio format, %d Hz, %s, %d-bit", sampleRate, chStr, bitsPerSample)
}

var matcherMidi = fileMatcher{
	name:   "midi",
	minLen: 14,
	mime:   "audio/midi",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
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
	mime:   "image/vnd.adobe.photoshop",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 16 && HasPrefix(b, "\x38\x42\x50\x53")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "Photoshop document"
	},
}

var matcherAvi = fileMatcher{
	name:   "avi",
	minLen: 33,
	mime:   "video/x-msvideo",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:11], "AVI")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "AVI file"
	},
}

var matcherAsf = fileMatcher{
	name:   "asf",
	minLen: 16,
	mime:   "video/x-ms-asf",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb >= 16 && HasPrefix(b, "\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "ASF media file"
	},
}

var matcherWebp = fileMatcher{
	name:   "webp",
	minLen: 33,
	mime:   "image/webp",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:12], "WEBP")
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeWebP(b)
	},
}

func describeWebP(b []byte) string {
	if len(b) < 16 {
		return "Google WebP file"
	}
	switch {
	case Equal(b[12:16], "VP8 "):
		// Lossy VP8 key frame: 3-byte frame tag + start code 0x9D 0x01 0x2A.
		if len(b) >= 30 && b[20]&0x01 == 0 && b[23] == 0x9D && b[24] == 0x01 && b[25] == 0x2A {
			width := (int(b[26]) | int(b[27])<<8) & 0x3FFF
			height := (int(b[28]) | int(b[29])<<8) & 0x3FFF
			if width > 0 && height > 0 {
				return fmt.Sprintf("Google WebP file (lossy, %d x %d)", width, height)
			}
		}
		return "Google WebP file (lossy)"
	case Equal(b[12:16], "VP8L"):
		return "Google WebP file (lossless)"
	case Equal(b[12:16], "VP8X"):
		// Extended: flags at byte 20; canvas dims at bytes 24–29 (3-byte LE each, value = dim-1).
		if len(b) >= 30 {
			flags := b[20]
			width := (int(b[24]) | int(b[25])<<8 | int(b[26])<<16) + 1
			height := (int(b[27]) | int(b[28])<<8 | int(b[29])<<16) + 1
			variant := "extended"
			if flags&0x02 != 0 {
				variant = "animated"
			}
			return fmt.Sprintf("Google WebP file (%s, %d x %d)", variant, width, height)
		}
		return "Google WebP file (extended)"
	default:
		return "Google WebP file"
	}
}
