package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
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
		{name: "pkcs7-der", data: append([]byte("\x30\x82\x01\x00\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"), make([]byte, 16)...), desc: "DER Encoded PKCS#7 Signed Data", mime: "application/pkcs7-signature"},
		{name: "szdd", data: append([]byte("SZDD\x88\xF0\x27\x33"), make([]byte, 8)...), desc: "MS Compress archive data, SZDD variant", mime: "application/x-ms-compress"},
		{name: "crda-regdb", data: append([]byte("RGDB\x00\x00\x00\x02"), make([]byte, 16)...), desc: "CRDA wireless regulatory database file", mime: "application/octet-stream"},
		{name: "wasm", data: []byte("\x00asm"), desc: "WebAssembly binary", mime: "application/octet-stream"},
		{name: "flv", data: []byte("FLV"), desc: "FLV video file", mime: "application/octet-stream"},
		{name: "woff", data: []byte("wOFF"), desc: "WOFF font", mime: "application/octet-stream"},
		{name: "woff2", data: []byte("wOF2"), desc: "WOFF2 font", mime: "application/octet-stream"},
		{name: "bmp", data: append([]byte{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 41)...), desc: "BMP image", mime: "image/bmp"},
		{name: "wmf-placeable", data: append([]byte("\xD7\xCD\xC6\x9A"), make([]byte, 16)...), desc: "Windows metafile", mime: "image/wmf"},
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
		{name: "cur", data: append([]byte("\x00\x00\x02\x00\x01\x00"), make([]byte, 12)...), desc: "MS Windows cursor resource", mime: "image/x-icon"},
		{name: "sqlite", data: []byte("SQLite format 3\x00...."), desc: "SQLite database", mime: "application/octet-stream"},
		{name: "chm", data: append([]byte("ITSF"), make([]byte, 12)...), desc: "MS Windows HtmlHelp Data", mime: "application/vnd.ms-htmlhelp"},
		{name: "coff-i386", data: []byte{0x4C, 0x01, 0x06, 0x00, 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0, 0, 0, 0}, desc: "Intel i386 COFF object file", mime: "application/x-object"},
		{name: "coff-x64", data: []byte{0x64, 0x86, 0x08, 0x00, 0, 0, 0, 0, 0x80, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0, 0, 0, 0}, desc: "x86-64 COFF object file", mime: "application/x-object"},
		{name: "pcapng", data: append([]byte("\x0A\x0D\x0D\x0A"), make([]byte, 13)...), desc: "PCAP-ng capture file", mime: "application/octet-stream"},
		{name: "pcap", data: append([]byte("\xD4\xC3\xB2\xA1"), make([]byte, 13)...), desc: "PCAP capture file", mime: "application/octet-stream"},
		{name: "gettext-mo", data: append([]byte("\xDE\x12\x04\x95\x00\x00\x00\x00"), make([]byte, 24)...), desc: "GNU gettext message catalog", mime: "application/x-gettext-translation"},
		{name: "crx", data: append([]byte("Cr24\x02\x00\x00\x00\x10\x00\x00\x00"), make([]byte, 8)...), desc: "Google Chrome extension", mime: "application/x-chrome-extension"},
		{name: "rcc", data: append([]byte("qres"), make([]byte, 12)...), desc: "Qt Binary Resource file", mime: "application/octet-stream"},
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
		{name: "xml-utf8-bom", data: []byte("\xEF\xBB\xBF<?xml version=\"1.0\"?><x/>"), desc: "XML document", mime: "application/octet-stream"},
		{name: "xml-utf16le-bom", data: []byte("\xFF\xFE<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00\"\x001\x00.\x000\x00\"\x00?\x00>\x00<\x00x\x00/\x00>\x00"), desc: "XML document", mime: "application/octet-stream"},
		{name: "json", data: []byte("{\"a\":1,\"b\":2}"), desc: "JSON data", mime: "application/octet-stream"},
		{name: "qml", data: []byte("import QtQuick 2.0\nItem {\n  property int count: 0\n}\n"), descLike: "ASCII text, QML source", mime: "text/plain"},
		{name: "qml-import-only", data: []byte("import QtQuick 2.0\nimport QtQuick.Controls 2.5\nItem {\n  id: root\n}\n"), descLike: "QML source", mime: "text/plain"},
		{name: "ruby-script", data: []byte("require 'json'\nclass Demo\n  def run\n    puts 'ok'\n  end\nend\n"), descLike: "Ruby script", mime: "text/plain"},
		{name: "powershell-not-ini", data: []byte("[CmdletBinding()]\nparam(\n[string]$Name = \"x\"\n)\n"), descLike: "PowerShell script", mime: "text/plain"},
		{name: "not-ini-weak-structure", data: []byte("[OnlySection]\nnotes line without equals\njust text\nk=v\n"), descLike: "ASCII text", mime: "text/plain"},
		{name: "ascii-text", data: []byte("hello world"), desc: "ASCII text", mime: "text/plain"},
		{name: "utf8-text", data: []byte("hello, \u4e16\u754c"), desc: "UTF-8 text", mime: "text/plain"},
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
			if _, err := os.Stat(tt.path); err != nil {
				t.Skipf("fixture unavailable: %v", err)
			}
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

func TestDetectFileType_ZipSubtypes(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()

	makeZip := func(name string, entries map[string]string) string {
		t.Helper()
		p := filepath.Join(tmp, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatalf("os.Create(%q) error = %v", p, err)
		}

		zw := zip.NewWriter(f)
		for entryName, content := range entries {
			w, err := zw.Create(entryName)
			if err != nil {
				t.Fatalf("zip create %q error = %v", entryName, err)
			}
			if _, err := io.WriteString(w, content); err != nil {
				t.Fatalf("zip write %q error = %v", entryName, err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zip close error = %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("file close error = %v", err)
		}
		return p
	}

	silverlight := makeZip("sample.xap", map[string]string{
		"AppManifest.xaml": "<Deployment />",
		"AssemblyInfo.cs":  "class X {}",
	})
	desc, err := detectFileType(silverlight)
	if err != nil {
		t.Fatalf("detectFileType(silverlight) error = %v", err)
	}
	if desc != "Microsoft Silverlight Application" {
		t.Fatalf("silverlight desc = %q, want %q", desc, "Microsoft Silverlight Application")
	}

	ooxml := makeZip("sample.accdt", map[string]string{
		"[Content_Types].xml": "<Types/>",
		"_rels/.rels":         "<Relationships/>",
		"docProps/core.xml":   "<cp:coreProperties/>",
	})
	desc, err = detectFileType(ooxml)
	if err != nil {
		t.Fatalf("detectFileType(ooxml) error = %v", err)
	}
	if desc != "Microsoft OOXML" {
		t.Fatalf("ooxml desc = %q, want %q", desc, "Microsoft OOXML")
	}
}

func TestDetectFileType_DebianArSubtype(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "sample.deb")

	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("os.Create(%q) error = %v", p, err)
	}

	add := func(name string, body string) {
		t.Helper()
		if len(name) > 16 {
			t.Fatalf("ar test entry name too long: %q", name)
		}
		if _, err := io.WriteString(f, fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0644, len(body))); err != nil {
			t.Fatalf("ar write header %q error = %v", name, err)
		}
		if _, err := io.WriteString(f, body); err != nil {
			t.Fatalf("ar write body %q error = %v", name, err)
		}
		if len(body)%2 != 0 {
			if _, err := io.WriteString(f, "\n"); err != nil {
				t.Fatalf("ar write pad %q error = %v", name, err)
			}
		}
	}

	if _, err := io.WriteString(f, "!<arch>\n"); err != nil {
		t.Fatalf("ar write magic error = %v", err)
	}
	add("debian-binary", "2.0\n")
	add("control.tar.xz", "dummy")
	add("data.tar.zst", "dummy")
	if err := f.Close(); err != nil {
		t.Fatalf("file close error = %v", err)
	}

	desc, err := detectFileType(p)
	if err != nil {
		t.Fatalf("detectFileType(deb) error = %v", err)
	}
	want := "Debian binary package (format 2.0), with control.tar.xz, data compression zst"
	if desc != want {
		t.Fatalf("deb desc = %q, want %q", desc, want)
	}

	if got := mimeForDescription(desc); got != "application/vnd.debian.binary-package" {
		t.Fatalf("deb mime = %q, want %q", got, "application/vnd.debian.binary-package")
	}
}

func TestDetectFromBytes_GlibcLocalePathFallback(t *testing.T) {
	t.Parallel()

	bin := []byte{0x00, 0x01, 0xB0, 0x7F, 0x00, 0x10}
	got, err := detectFromBytes(bin, "/usr/lib/locale/en_GB.utf8/LC_ADDRESS", nil)
	if err != nil {
		t.Fatalf("detectFromBytes(glibc locale) error = %v", err)
	}
	if got != "glibc locale file LC_ADDRESS" {
		t.Fatalf("detectFromBytes(glibc locale) = %q, want %q", got, "glibc locale file LC_ADDRESS")
	}
	if mime := mimeForDescription(got); mime != "application/octet-stream" {
		t.Fatalf("mimeForDescription(glibc locale) = %q, want %q", mime, "application/octet-stream")
	}
}
