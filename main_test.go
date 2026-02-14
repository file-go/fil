package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureCase struct {
	name     string
	data     []byte
	desc     string
	descLike string
	mime     string
}

func TestDetectFromBytes_Fixtures(t *testing.T) {
	t.Parallel()

	ftyp := func(brand string) []byte {
		b := make([]byte, 32)
		copy(b[4:8], []byte("ftyp"))
		copy(b[8:12], []byte(brand))
		return b
	}

	tests := []fixtureCase{
		{name: "png", data: append([]byte("\x89PNG\x0d\x0a\x1a\x0a"), make([]byte, 24)...), desc: "PNG image data", mime: "image/png"},
		{name: "gif89a", data: append([]byte("GIF89a"), make([]byte, 16)...), desc: "GIF image data", mime: "image/gif"},
		{name: "jpeg", data: append([]byte("\xff\xd8"), make([]byte, 32)...), desc: "JPEG / jpg image data", mime: "image/jpeg"},
		{name: "dds", data: []byte("DDS "), desc: "DDS image data", mime: "image/vnd-ms.dds"},
		{name: "exr", data: []byte("\x76\x2F\x31\x01"), desc: "OpenEXR image data", mime: "image/x-exr"},
		{name: "hdr", data: []byte("#?RADIANCE"), desc: "Radiance HDR image data", mime: "image/vnd.radiance"},
		{name: "icns", data: append([]byte("icns"), make([]byte, 4)...), desc: "Apple icon image", mime: "image/icns"},
		{name: "java-class", data: append([]byte("\xca\xfe\xba\xbe"), make([]byte, 8)...), desc: "Java class file", mime: "application/octet-stream"},
		{name: "dex", data: append([]byte("dex\n"), make([]byte, 8)...), desc: "Android dex file", mime: "application/octet-stream"},
		{name: "bzip2", data: []byte("BZh91"), desc: "bzip2 compressed data", mime: "application/x-bzip2"},
		{name: "xz", data: []byte("\xFD7zXZ\x00"), desc: "XZ compressed data", mime: "application/x-xz"},
		{name: "zstd", data: []byte("\x28\xB5\x2F\xFD"), desc: "Zstandard compressed data", mime: "application/zstd"},
		{name: "lz4", data: []byte("\x04\x22\x4D\x18"), desc: "LZ4 compressed data", mime: "application/x-lz4"},
		{name: "lzip", data: []byte("LZIP"), desc: "LZIP compressed data", mime: "application/x-lzip"},
		{name: "gzip", data: append([]byte("\x1f\x8b"), make([]byte, 9)...), desc: "gzip compressed data", mime: "application/gzip"},
		{name: "wasm", data: []byte("\x00asm"), desc: "WebAssembly binary", mime: "application/octet-stream"},
		{name: "flv", data: []byte("FLV"), desc: "FLV video file", mime: "application/octet-stream"},
		{name: "woff", data: []byte("wOFF"), desc: "WOFF font", mime: "application/octet-stream"},
		{name: "woff2", data: []byte("wOF2"), desc: "WOFF2 font", mime: "application/octet-stream"},
		{name: "bmp", data: append([]byte{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 41)...), desc: "BMP image", mime: "image/bmp"},
		{name: "pdf", data: append([]byte("%PDF"), make([]byte, 47)...), desc: "PDF document", mime: "application/pdf"},
		{name: "tiff", data: append([]byte{0x49, 0x49, 0x2A, 0x00}, make([]byte, 13)...), desc: "TIFF image data", mime: "image/tiff"},
		{name: "mp3-id3", data: append([]byte("ID3"), make([]byte, 14)...), desc: "MP3 audio file", mime: "application/octet-stream"},
		{name: "avif", data: ftyp("avif"), desc: "AVIF image", mime: "image/avif"},
		{name: "heif", data: ftyp("heic"), desc: "HEIF image", mime: "image/heif"},
		{name: "jxl", data: []byte("\xFF\x0A"), desc: "JPEG XL image data", mime: "image/jxl"},
		{name: "jp2", data: []byte("\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A"), desc: "JPEG 2000 image data", mime: "image/jp2"},
		{name: "m4a", data: ftyp("M4A "), desc: "M4A audio", mime: "audio/mp4"},
		{name: "quicktime", data: ftyp("qt  "), desc: "QuickTime movie file", mime: "video/quicktime"},
		{name: "3gpp", data: ftyp("3gp5"), desc: "3GPP video file", mime: "video/3gpp"},
		{name: "m4v", data: ftyp("M4V "), desc: "M4V video file", mime: "video/x-m4v"},
		{name: "mp4", data: ftyp("isom"), desc: "MP4 video file", mime: "video/mp4"},
		{name: "rar", data: []byte("\x52\x61\x72\x21\x1A\x07\x00"), desc: "RAR archive data", mime: "application/vnd.rar"},
		{name: "7zip", data: append([]byte("\x37\x7A\xBC\xAF\x27\x1C"), make([]byte, 11)...), desc: "7zip archive data", mime: "application/x-7z-compressed"},
		{name: "ico", data: append([]byte("\x00\x00\x01\x00"), make([]byte, 13)...), desc: "MS Windows icon resource", mime: "image/x-icon"},
		{name: "sqlite", data: []byte("SQLite format 3\x00...."), desc: "SQLite database", mime: "application/octet-stream"},
		{name: "pcapng", data: append([]byte("\x0A\x0D\x0D\x0A"), make([]byte, 13)...), desc: "PCAP-ng capture file", mime: "application/octet-stream"},
		{name: "pcap", data: append([]byte("\xD4\xC3\xB2\xA1"), make([]byte, 13)...), desc: "PCAP capture file", mime: "application/octet-stream"},
		{name: "flac", data: append([]byte("fLaC"), make([]byte, 13)...), desc: "FLAC audio format", mime: "application/octet-stream"},
		{name: "midi", data: []byte("MThd\x00\x00\x00\x06\x00\x01\x00\x01\x01\xE0"), descLike: "Standard MIDI data (format 1)", mime: "audio/midi"},
		{name: "cab", data: append([]byte("MSCF"), make([]byte, 13)...), desc: "Microsoft Cabinet file", mime: "application/octet-stream"},
		{name: "psd", data: append([]byte("8BPS"), make([]byte, 13)...), desc: "Photoshop document", mime: "image/vnd.adobe.photoshop"},
		{name: "asf", data: []byte("\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"), desc: "ASF media file", mime: "video/x-ms-asf"},
		{name: "webp", data: func() []byte {
			b := make([]byte, 33)
			copy(b[:3], []byte("RIF"))
			copy(b[8:12], []byte("WEBP"))
			return b
		}(), desc: "Google Webp file", mime: "image/webp"},
		{name: "rtf", data: append([]byte("{\\rtf1"), make([]byte, 27)...), desc: "Rich Text Format", mime: "application/octet-stream"},
		{name: "html", data: []byte("<!DOCTYPE html><html><body>ok</body></html>"), desc: "HTML document", mime: "application/octet-stream"},
		{name: "svg", data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), desc: "SVG Scalable Vector Graphics image", mime: "image/svg+xml"},
		{name: "xml", data: append([]byte("<?xml version=\"1.0\"?><x/>"), make([]byte, 12)...), desc: "XML document", mime: "application/octet-stream"},
		{name: "json", data: []byte("{\"a\":1,\"b\":2}"), desc: "JSON data", mime: "application/octet-stream"},
		{name: "ascii-text", data: []byte("hello world"), desc: "ASCII text", mime: "text/plain"},
		{name: "utf8-text", data: []byte("hello, 世界"), desc: "UTF-8 text", mime: "text/plain"},
		{name: "data-fallback", data: []byte{0x00, 0x01, 0x02, 0x03, 0x04}, desc: "data", mime: "application/octet-stream"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := detectFromBytes(tt.data, tt.name, nil)
			if err != nil {
				t.Fatalf("detectFromBytes() error = %v", err)
			}
			if tt.desc != "" && got != tt.desc {
				t.Fatalf("detectFromBytes() = %q, want %q", got, tt.desc)
			}
			if tt.descLike != "" && !strings.Contains(got, tt.descLike) {
				t.Fatalf("detectFromBytes() = %q, want substring %q", got, tt.descLike)
			}
			if gotMime := mimeForDescription(got); gotMime != tt.mime {
				t.Fatalf("mimeForDescription(%q) = %q, want %q", got, gotMime, tt.mime)
			}
		})
	}
}

func TestDetectFileType_ProjectFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		descLike string
		mime     string
	}{
		{path: filepath.Join("testdata", "src", "WiFi.cpp"), descLike: "ASCII text, C++ source", mime: "text/plain"},
		{path: filepath.Join("testdata", "src", "WiFiClient.cpp"), descLike: "ASCII text, C++ source", mime: "text/plain"},
		{path: filepath.Join("testdata", "powershell", "Get-KapeModuleBinaries.ps1"), descLike: "ASCII text, PowerShell script", mime: "text/plain"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			got, err := detectFileType(tt.path)
			if err != nil {
				t.Fatalf("detectFileType(%q) error = %v", tt.path, err)
			}
			if !strings.Contains(got, tt.descLike) {
				t.Fatalf("detectFileType(%q) = %q, want substring %q", tt.path, got, tt.descLike)
			}
			if gotMime := mimeForDescription(got); gotMime != tt.mime {
				t.Fatalf("mimeForDescription(%q) = %q, want %q", got, gotMime, tt.mime)
			}
		})
	}
}

func TestEmitJSON(t *testing.T) {
	t.Parallel()

	// Capture stdout so we can validate the JSONL payload.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	emitJSON("example.png", "PNG image data", true, "")

	if err := w.Close(); err != nil {
		t.Fatalf("close writer error = %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	line := strings.TrimSpace(string(bytes.TrimSpace(out)))
	var got jsonLine
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", line, err)
	}

	if got.Path != "example.png" {
		t.Fatalf("path = %q, want %q", got.Path, "example.png")
	}
	if got.Type != "PNG image data" {
		t.Fatalf("type = %q, want %q", got.Type, "PNG image data")
	}
	if got.Mime != "image/png" {
		t.Fatalf("mime = %q, want %q", got.Mime, "image/png")
	}
	if got.Error != "" {
		t.Fatalf("error = %q, want empty", got.Error)
	}
}
