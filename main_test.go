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
		{name: "java-class", data: append([]byte("\xca\xfe\xba\xbe"), make([]byte, 8)...), desc: "Java class file", mime: "application/java"},
		{name: "java-serialization", data: append([]byte("\xAC\xED\x00\x05"), make([]byte, 12)...), desc: "Java serialized object", mime: "application/x-java-serialized-object"},
		{name: "dex", data: append([]byte("dex\n"), make([]byte, 8)...), desc: "Android dex file", mime: "application/octet-stream"},
		{name: "jmod", data: append([]byte("JMOD\x00\x01"), make([]byte, 12)...), desc: "Java JMOD module", mime: "application/x-java-jmod"},
		{name: "hprof", data: append([]byte("JAVA PROFILE 1.0.2\x00"), make([]byte, 12)...), desc: "Java HPROF heap dump", mime: "application/x-java-hprof"},
		{name: "jks", data: []byte("\xFE\xED\xFE\xED\x00\x00\x00\x02\x00\x00\x00\x00"), desc: "Java JKS keystore", mime: "application/x-java-keystore"},
		{name: "jceks", data: []byte("\xCE\xCE\xCE\xCE\x00\x00\x00\x01\x00\x00\x00\x00"), desc: "Java JCEKS keystore", mime: "application/x-java-keystore"},
		{name: "pem-cert", data: []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"), desc: "PEM certificate", mime: "application/x-pem-file"},
		{name: "pem-private", data: []byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"), desc: "PEM private key", mime: "application/x-pem-file"},
		{name: "pem-public", data: []byte("-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"), desc: "PEM public key", mime: "application/x-pem-file"},
		{name: "pem-csr", data: []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n"), desc: "PEM certificate request", mime: "application/pkcs10"},
		{name: "openssh-private", data: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), desc: "OpenSSH private key", mime: "application/x-pem-file"},
		{name: "pkcs12", data: append([]byte{0x30, 0x1A, 0x02, 0x01, 0x03, 0x30, 0x0F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}, make([]byte, 32)...), desc: "PKCS#12 key store", mime: "application/x-pkcs12"},
		{name: "x509-der", data: append([]byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x81, 0xE8, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x06, 0x03, 0x55, 0x04, 0x03, 0x06, 0x03, 0x55, 0x1D, 0x13}, make([]byte, 32)...), desc: "X.509 certificate (DER)", mime: "application/pkix-cert"},
		{name: "pkcs8-der", data: append([]byte{0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x1A}, make([]byte, 32)...), desc: "PKCS#8 private key (DER)", mime: "application/pkcs8"},
		{name: "spki-der", data: append([]byte{0x30, 0x30, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x1F, 0x00}, make([]byte, 32)...), desc: "X.509 SubjectPublicKeyInfo (DER public key)", mime: "application/pkix-key"},
		{name: "bzip2", data: []byte("BZh91"), desc: "bzip2 compressed data", mime: "application/x-bzip2"},
		{name: "xz", data: []byte("\xFD7zXZ\x00"), desc: "XZ compressed data", mime: "application/x-xz"},
		{name: "zstd", data: []byte("\x28\xB5\x2F\xFD"), desc: "Zstandard compressed data", mime: "application/zstd"},
		{name: "lz4", data: []byte("\x04\x22\x4D\x18"), desc: "LZ4 compressed data", mime: "application/x-lz4"},
		{name: "lzip", data: []byte("LZIP"), desc: "LZIP compressed data", mime: "application/x-lzip"},
		{name: "gzip", data: append([]byte("\x1f\x8b"), make([]byte, 9)...), desc: "gzip compressed data", mime: "application/gzip"},
		{name: "pkcs7-der", data: append([]byte("\x30\x82\x01\x00\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"), make([]byte, 16)...), desc: "DER Encoded PKCS#7 Signed Data", mime: "application/pkcs7-signature"},
		{name: "szdd", data: append([]byte("SZDD\x88\xF0\x27\x33"), make([]byte, 8)...), desc: "MS Compress archive data, SZDD variant", mime: "application/x-ms-compress"},
		{name: "crda-regdb", data: append([]byte("RGDB\x00\x00\x00\x02"), make([]byte, 16)...), desc: "CRDA wireless regulatory database file", mime: "application/octet-stream"},
		{name: "wasm", data: []byte("\x00asm"), desc: "WebAssembly binary", mime: "application/wasm"},
		{name: "flv", data: []byte("FLV"), desc: "FLV video file", mime: "video/x-flv"},
		{name: "woff", data: []byte("wOFF"), desc: "WOFF font", mime: "font/woff"},
		{name: "woff2", data: []byte("wOF2"), desc: "WOFF2 font", mime: "font/woff2"},
		{name: "otf", data: []byte("OTTO\x00\x01\x00\x00"), desc: "OpenType font data", mime: "font/otf"},
		{name: "eot", data: func() []byte {
			b := make([]byte, 40)
			// EOT version 0x00010000
			b[8] = 0x00
			b[9] = 0x00
			b[10] = 0x01
			b[11] = 0x00
			// EOT magic 'LP' at offset 34.
			b[34] = 0x4C
			b[35] = 0x50
			return b
		}(), desc: "Embedded OpenType font", mime: "application/vnd.ms-fontobject"},
		{name: "bmp", data: append([]byte{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 41)...), desc: "BMP image", mime: "image/bmp"},
		{name: "wmf-placeable", data: append([]byte("\xD7\xCD\xC6\x9A"), make([]byte, 16)...), desc: "Windows metafile", mime: "image/wmf"},
		{name: "pdf", data: append([]byte("%PDF"), make([]byte, 47)...), desc: "PDF document", mime: "application/pdf"},
		{name: "indd", data: append([]byte{0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5, 0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D}, make([]byte, 16)...), desc: "Adobe InDesign document", mime: "application/x-indesign"},
		{name: "mobi", data: func() []byte {
			b := make([]byte, 80)
			copy(b[60:68], []byte("BOOKMOBI"))
			return b
		}(), desc: "Mobipocket e-book", mime: "application/x-mobipocket-ebook"},
		{name: "lit", data: append([]byte("ITOLITLS"), make([]byte, 24)...), desc: "Microsoft Reader eBook", mime: "application/x-ms-reader"},
		{name: "xar", data: append([]byte("xar!"), make([]byte, 32)...), desc: "XAR archive (Apple installer package)", mime: "application/x-xar"},
		{name: "rpm", data: append([]byte("\xED\xAB\xEE\xDB\x03\x00\x00\x00"), make([]byte, 120)...), desc: "RPM package data", mime: "application/x-rpm"},
		{name: "apple-bom", data: append([]byte("BOMStore"), make([]byte, 16)...), desc: "Apple BOM archive", mime: "application/x-apple-bom"},
		{name: "appledouble", data: append([]byte("\x00\x05\x16\x07"), make([]byte, 16)...), desc: "AppleDouble encoded file", mime: "application/applefile"},
		{name: "plist-binary", data: append([]byte("bplist00"), make([]byte, 16)...), desc: "Apple property list", mime: "application/x-plist"},
		{name: "ds-store", data: append([]byte{0x00, 0x00, 0x00, 0x01, 'B', 'u', 'd', '1'}, make([]byte, 20)...), desc: "Apple DS_Store metadata", mime: "application/octet-stream"},
		{name: "apfs", data: func() []byte {
			b := make([]byte, 64)
			copy(b[32:36], []byte("NXSB"))
			return b
		}(), desc: "Apple APFS filesystem", mime: "application/octet-stream"},
		{name: "hfs", data: func() []byte {
			b := make([]byte, 1100)
			copy(b[1024:1026], []byte("H+"))
			return b
		}(), desc: "Apple HFS/HFS+ filesystem", mime: "application/octet-stream"},
		{name: "ewf", data: append([]byte("EVF\x09\x0D\x0A\xFF\x00"), make([]byte, 24)...), desc: "Expert Witness Compression Format (EWF) image", mime: "application/x-ewf"},
		{name: "dwg", data: append([]byte("AC1027"), make([]byte, 18)...), desc: "AutoCAD DWG drawing", mime: "image/vnd.dwg"},
		{name: "tiff", data: append([]byte{0x49, 0x49, 0x2A, 0x00}, make([]byte, 13)...), desc: "TIFF image data", mime: "image/tiff"},
		{name: "mp3-id3", data: append([]byte("ID3"), make([]byte, 14)...), desc: "MP3 audio file", mime: "audio/mpeg"},
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
		{name: "sqlite", data: []byte("SQLite format 3\x00...."), desc: "SQLite database", mime: "application/x-sqlite3"},
		{name: "chm", data: append([]byte("ITSF"), make([]byte, 12)...), desc: "MS Windows HtmlHelp Data", mime: "application/vnd.ms-htmlhelp"},
		{name: "ese-db", data: func() []byte {
			b := make([]byte, 256)
			// Checksum as displayed (big-endian bytes).
			b[0], b[1], b[2], b[3] = 0x43, 0xE4, 0xF6, 0x36
			// ESE marker 0x89ABCDEF at offset 4 (little-endian).
			b[4], b[5], b[6], b[7] = 0xEF, 0xCD, 0xAB, 0x89
			// Version 0x620 at offset 8 (little-endian).
			b[8], b[9], b[10], b[11] = 0x20, 0x06, 0x00, 0x00
			// Page size 8192 at offset 236 (little-endian).
			b[236], b[237], b[238], b[239] = 0x00, 0x20, 0x00, 0x00
			return b
		}(), desc: "Extensible storage engine DataBase, version 0x620, checksum 0x43e4f636, page size 8192", mime: "application/x-ms-ese"},
		{name: "ese-log", data: []byte{0x98, 0x26, 0xEE, 0x66, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x80, 0x00, 0x00, 0x20, 0x28, 0x24, 0x03, 0x13}, desc: "Extensible storage engine transaction log", mime: "application/x-ms-ese-log"},
		{name: "prefetch-classic", data: []byte{0x1A, 0x00, 0x00, 0x00, 'S', 'C', 'C', 'A', 0x00, 0x00, 0x00, 0x00}, desc: "Windows Prefetch file", mime: "application/octet-stream"},
		{name: "prefetch-compressed", data: []byte{'M', 'A', 'M', 0x04, 0xF2, 0x29, 0x00, 0x00, 0x94, 0x77, 0x87, 0x89}, desc: "Windows Prefetch file", mime: "application/octet-stream"},
		{name: "coff-i386", data: []byte{0x4C, 0x01, 0x06, 0x00, 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0, 0, 0, 0}, desc: "Intel i386 COFF object file", mime: "application/x-object"},
		{name: "coff-x64", data: []byte{0x64, 0x86, 0x08, 0x00, 0, 0, 0, 0, 0x80, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0, 0, 0, 0}, desc: "x86-64 COFF object file", mime: "application/x-object"},
		{name: "redis-rdb", data: append([]byte("REDIS0011"), make([]byte, 24)...), desc: "Redis database dump", mime: "application/x-redis-rdb"},
		{name: "dbf", data: func() []byte {
			b := make([]byte, 65)
			b[0] = 0x03 // dBASE III
			b[1] = 0x24 // YY
			b[2] = 0x01 // MM
			b[3] = 0x1A // DD
			// header length = 65 (0x41)
			b[8], b[9] = 0x41, 0x00
			// record length = 32
			b[10], b[11] = 0x20, 0x00
			// header terminator at headerLen-1
			b[64] = 0x0D
			return b
		}(), desc: "dBase DBF database", mime: "application/x-dbf"},
		{name: "outlook-pst-ost", data: func() []byte {
			b := make([]byte, 32)
			copy(b[0:4], []byte("!BDN"))
			copy(b[8:10], []byte("SM"))
			// Version 23 (Unicode PST/OST), little-endian.
			b[10], b[11] = 0x17, 0x00
			return b
		}(), desc: "Microsoft Outlook PST/OST message store (Unicode)", mime: "application/vnd.ms-outlook"},
		{name: "outlook-msg", data: func() []byte {
			b := make([]byte, 512)
			copy(b[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
			copy(b[64:], asciiToUTF16LE("__properties_version1.0"))
			copy(b[180:], asciiToUTF16LE("__substg1.0_1000001F"))
			return b
		}(), desc: "Microsoft Outlook MSG message", mime: "application/vnd.ms-outlook"},
		{name: "ms-access", data: func() []byte {
			b := make([]byte, 256)
			copy(b[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
			copy(b[64:], []byte("Standard Jet DB"))
			return b
		}(), desc: "Microsoft Access database", mime: "application/x-msaccess"},
		{name: "shapefile", data: func() []byte {
			b := make([]byte, 100)
			copy(b[0:4], []byte{0x00, 0x00, 0x27, 0x0A})
			// version = 1000 LE at offset 28
			b[28], b[29], b[30], b[31] = 0xE8, 0x03, 0x00, 0x00
			// shape type = 5 (Polygon) LE at offset 32
			b[32], b[33], b[34], b[35] = 0x05, 0x00, 0x00, 0x00
			return b
		}(), desc: "ESRI Shapefile data", mime: "application/x-esri-shape"},
		{name: "las", data: append([]byte("LASF"), make([]byte, 40)...), desc: "ASPRS LAS LiDAR data", mime: "application/vnd.las"},
		{name: "geopackage", data: func() []byte {
			b := make([]byte, 96)
			copy(b, []byte("SQLite format 3\x00"))
			copy(b[68:72], []byte("GPKG"))
			return b
		}(), desc: "OGC GeoPackage database", mime: "application/geopackage+sqlite3"},
		{name: "roslyn-pdb", data: append([]byte("BSJB\x01\x00\x01\x00PDB v1.0\x00"), make([]byte, 20)...), desc: "Microsoft Roslyn C# debugging symbols version 1.0", mime: "application/octet-stream"},
		{name: "magic-mgc", data: append([]byte("\x1C\x04\x1E\xF1"), make([]byte, 16)...), desc: "magic binary file for file(1) cmd", mime: "application/octet-stream"},
		{name: "pcapng", data: append([]byte("\x0A\x0D\x0D\x0A"), make([]byte, 13)...), desc: "PCAP-ng capture file", mime: "application/octet-stream"},
		{name: "pcap", data: append([]byte("\xD4\xC3\xB2\xA1"), make([]byte, 13)...), desc: "PCAP capture file", mime: "application/octet-stream"},
		{name: "tnef", data: append([]byte{0x78, 0x9F, 0x3E, 0x22, 0x01, 0x00}, make([]byte, 20)...), desc: "TNEF attachment data", mime: "application/ms-tnef"},
		{name: "gettext-mo", data: append([]byte("\xDE\x12\x04\x95\x00\x00\x00\x00"), make([]byte, 24)...), desc: "GNU gettext message catalog", mime: "application/x-gettext-translation"},
		{name: "gir-typelib", data: append([]byte("GOBJ\nMETADATA\r\n\x1A"), make([]byte, 20)...), desc: "G-IR binary database", mime: "application/octet-stream"},
		{name: "crx", data: append([]byte("Cr24\x02\x00\x00\x00\x10\x00\x00\x00"), make([]byte, 8)...), desc: "Google Chrome extension", mime: "application/x-chrome-extension"},
		{name: "rcc", data: append([]byte("qres"), make([]byte, 12)...), desc: "Qt Binary Resource file", mime: "application/octet-stream"},
		{name: "flac", data: append([]byte("fLaC"), make([]byte, 13)...), desc: "FLAC audio format", mime: "audio/flac"},
		{name: "midi", data: []byte("MThd\x00\x00\x00\x06\x00\x01\x00\x01\x01\xE0"), descLike: "Standard MIDI data (format 1)", mime: "audio/midi"},
		{name: "cab", data: append([]byte("MSCF"), make([]byte, 13)...), desc: "Microsoft Cabinet file", mime: "application/vnd.ms-cab-compressed"},
		{name: "psd", data: append([]byte("8BPS"), make([]byte, 13)...), desc: "Photoshop document", mime: "image/vnd.adobe.photoshop"},
		{name: "asf", data: []byte("\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"), desc: "ASF media file", mime: "video/x-ms-asf"},
		{name: "webp", data: func() []byte {
			b := make([]byte, 33)
			copy(b[:3], []byte("RIF"))
			copy(b[8:12], []byte("WEBP"))
			return b
		}(), desc: "Google Webp file", mime: "image/webp"},
		{name: "rtf", data: append([]byte("{\\rtf1"), make([]byte, 27)...), desc: "Rich Text Format", mime: "application/rtf"},
		{name: "html", data: []byte("<!DOCTYPE html><html><body>ok</body></html>"), desc: "HTML document", mime: "text/html"},
		{name: "binary-with-embedded-html", data: func() []byte {
			b := make([]byte, 2600)
			copy(b[:12], []byte{0x04, 0x00, 0x00, 0x00, 0x6A, 0x01, 0x00, 0x00, 0x01, 0xAD, 0x0D, 0x8B})
			copy(b[2200:], []byte("<!doctype html><html><head><meta charset=\"utf-8\"></head></html>"))
			return b
		}(), desc: "data", mime: "application/octet-stream"},
		{name: "svg", data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), desc: "SVG Scalable Vector Graphics image", mime: "image/svg+xml"},
		{name: "xml", data: append([]byte("<?xml version=\"1.0\"?><x/>"), make([]byte, 12)...), desc: "XML document", mime: "application/octet-stream"},
		{name: "scribus", data: []byte("<?xml version=\"1.0\"?><SCRIBUSUTF8NEW Version=\"1.5.8\"></SCRIBUSUTF8NEW>"), desc: "Scribus document", mime: "application/vnd.scribus"},
		{name: "dxf", data: []byte("0\nSECTION\n2\nHEADER\n9\n$ACADVER\n1\nAC1027\n0\nENDSEC\n0\nEOF\n"), desc: "AutoCAD DXF drawing exchange format", mime: "image/vnd.dxf"},
		{name: "step", data: []byte("ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('demo'),'2;1');\nENDSEC;\nDATA;\nENDSEC;\nEND-ISO-10303-21;\n"), desc: "STEP CAD model", mime: "model/step"},
		{name: "fb2", data: []byte("<?xml version=\"1.0\"?><FictionBook><description></description><body></body></FictionBook>"), desc: "FictionBook e-book", mime: "application/fb2+xml"},
		{name: "jnlp", data: []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<jnlp spec=\"1.0+\" codebase=\"https://example.com/app\"><information><title>Demo</title></information><resources/><application-desc main-class=\"com.example.Main\"/></jnlp>"), desc: "Java Web Start JNLP file", mime: "application/x-java-jnlp-file"},
		{name: "plist-xml", data: []byte("<?xml version=\"1.0\"?><!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"></plist>"), desc: "Apple property list", mime: "application/x-plist"},
		{name: "xml-utf8-bom", data: []byte("\xEF\xBB\xBF<?xml version=\"1.0\"?><x/>"), desc: "XML document", mime: "application/octet-stream"},
		{name: "xml-utf16le-bom", data: []byte("\xFF\xFE<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00\"\x001\x00.\x000\x00\"\x00?\x00>\x00<\x00x\x00/\x00>\x00"), desc: "XML document", mime: "application/octet-stream"},
		{name: "json", data: []byte("{\"a\":1,\"b\":2}"), desc: "JSON data", mime: "application/json"},
		{name: "qml", data: []byte("import QtQuick 2.0\nItem {\n  property int count: 0\n}\n"), descLike: "ASCII text, QML source", mime: "text/plain"},
		{name: "qml-import-only", data: []byte("import QtQuick 2.0\nimport QtQuick.Controls 2.5\nItem {\n  id: root\n}\n"), descLike: "QML source", mime: "text/plain"},
		{name: "ruby-script", data: []byte("require 'json'\nclass Demo\n  def run\n    puts 'ok'\n  end\nend\n"), descLike: "Ruby script", mime: "text/plain"},
		{name: "mbox-mailbox", data: []byte("From sender@example.com Sat Jan  1 00:00:00 2022\nDate: Sat, 1 Jan 2022 00:00:00 +0000\nFrom: Sender <sender@example.com>\nSubject: Test message\n\nBody\n"), descLike: "Mbox mailbox", mime: "application/mbox"},
		{name: "emlx-message", data: []byte("154\nDate: Sat, 1 Jan 2022 00:00:00 +0000\nFrom: Sender <sender@example.com>\nSubject: Test emlx\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nBody\n"), descLike: "Apple Mail message (emlx)", mime: "message/rfc822"},
		{name: "openssh-public", data: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNf9AbCdEfGhIjKlMnOpQrStUvWxYz01234567890 user@example\n"), descLike: "OpenSSH public key", mime: "text/plain"},
		{name: "openssh-authorized-keys", data: []byte("command=\"/usr/local/bin/restricted\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy1j6VQmWq6wM2jL5n84R3u7jJ8sG90qL5mQ0z4x9w0VnY7R example@host\n"), descLike: "OpenSSH authorized_keys", mime: "text/plain"},
		{name: "openssh-known-hosts", data: []byte("example.com,192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhVnYx2sT9q3mP8w1g0sD4r5a6b7c8d9e0f1g2h3i4\n"), descLike: "OpenSSH known_hosts", mime: "text/plain"},
		{name: "perl-nonutf-shebang", data: append([]byte("#!/usr/bin/perl\nprint \"ok\";\n# "), 0xE9), descLike: "Perl script", mime: "text/plain"},
		{name: "powershell-leading-comment-block", data: []byte("<#\n.SYNOPSIS\nExample\n#>\nfunction Invoke-Test {\n  param([string]$Path)\n  Write-Host $Path\n}\n"), descLike: "PowerShell script", mime: "text/plain"},
		{name: "powershell-not-ini", data: []byte("[CmdletBinding()]\nparam(\n[string]$Name = \"x\"\n)\n"), descLike: "PowerShell script", mime: "text/plain"},
		{name: "not-ini-weak-structure", data: []byte("[OnlySection]\nnotes line without equals\njust text\nk=v\n"), descLike: "ASCII text", mime: "text/plain"},
		{name: "ascii-text", data: []byte("hello world"), desc: "ASCII text", mime: "text/plain"},
		{name: "utf8-text", data: []byte("hello, \u4e16\u754c"), desc: "UTF-8 text", mime: "text/plain"},
		{name: "iso8859-text", data: []byte("caf\xe9 na\xefve fianc\xe9\nline two\n"), descLike: "Non-UTF text", mime: "text/plain"},
		{name: "data-fallback", data: []byte{0x00, 0x01, 0x02, 0x03, 0x04}, desc: "data", mime: "application/octet-stream"},

		// New binary formats
		{name: "aiff", data: func() []byte {
			b := make([]byte, 16)
			copy(b[0:4], []byte("FORM"))
			copy(b[8:12], []byte("AIFF"))
			return b
		}(), desc: "AIFF audio data", mime: "audio/aiff"},
		{name: "aifc", data: func() []byte {
			b := make([]byte, 16)
			copy(b[0:4], []byte("FORM"))
			copy(b[8:12], []byte("AIFC"))
			return b
		}(), desc: "AIFF-C audio data", mime: "audio/aiff"},
		{name: "aac-adts-mpeg4", data: []byte{0xFF, 0xF1, 0x50, 0x80, 0x00, 0x1F, 0xFC}, desc: "AAC audio data", mime: "audio/aac"},
		{name: "aac-adts-mpeg2", data: []byte{0xFF, 0xF9, 0x50, 0x80, 0x00, 0x1F, 0xFC}, desc: "AAC audio data", mime: "audio/aac"},
		{name: "postscript", data: []byte("%!PS-Adobe-3.0\n%%Creator: test\n%%EOF\n"), desc: "PostScript document", mime: "application/postscript"},
		{name: "eps", data: []byte("%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 200 200\n%%EOF\n"), desc: "Encapsulated PostScript document", mime: "application/postscript"},

		// New text subtypes
		{name: "go-source", data: []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"), descLike: "Go source", mime: "text/plain"},
		{name: "rust-source", data: []byte("use std::io;\n\nfn main() {\n\tlet mut s = String::new();\n\tio::stdin().read_line(&mut s).unwrap();\n}\n"), descLike: "Rust source", mime: "text/plain"},
		{name: "java-source", data: []byte("import java.util.ArrayList;\n\npublic class Main {\n\tpublic static void main(String[] args) {\n\t}\n}\n"), descLike: "Java source", mime: "text/plain"},
		{name: "dockerfile", data: []byte("FROM ubuntu:22.04\nRUN apt-get update\nCOPY . /app\nWORKDIR /app\nCMD [\"/app/start\"]\n"), descLike: "Dockerfile", mime: "text/plain"},
		{name: "makefile", data: []byte("build:\n\tgo build ./...\n\ntest:\n\tgo test ./...\n\nclean:\n\trm -f bin/*\n"), descLike: "Makefile", mime: "text/plain"},
		{name: "toml", data: []byte("[database]\nserver = \"192.168.1.1\"\nports = [8001, 8002]\nenabled = true\n\n[[servers]]\nhost = \"alpha\"\n"), descLike: "TOML", mime: "text/plain"},
		{name: "shell-env-bash", data: []byte("#!/usr/bin/env bash\nset -euo pipefail\necho hello\n"), descLike: "shell script", mime: "text/plain"},
		{name: "node-script", data: []byte("#!/usr/bin/env node\nconsole.log('hello');\n"), descLike: "Node.js script", mime: "text/plain"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, gotMime, err := detectFromBytes(tt.data, tt.name, nil)
			if err != nil {
				t.Fatalf("detectFromBytes() error = %v", err)
			}
			if tt.desc != "" && got != tt.desc {
				t.Fatalf("detectFromBytes() = %q, want %q", got, tt.desc)
			}
			if tt.descLike != "" && !strings.Contains(got, tt.descLike) {
				t.Fatalf("detectFromBytes() = %q, want substring %q", got, tt.descLike)
			}
			if gotMime != tt.mime {
				t.Fatalf("mime for %q = %q, want %q", got, gotMime, tt.mime)
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
			got, gotMime, err := detectFileType(tt.path)
			if err != nil {
				t.Fatalf("detectFileType(%q) error = %v", tt.path, err)
			}
			if !strings.Contains(got, tt.descLike) {
				t.Fatalf("detectFileType(%q) = %q, want substring %q", tt.path, got, tt.descLike)
			}
			if gotMime != tt.mime {
				t.Fatalf("mime for %q = %q, want %q", got, gotMime, tt.mime)
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

	emitJSON("example.png", "PNG image data", true, "image/png", "")

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

	checkZip := func(path, wantDesc, wantMime string) {
		t.Helper()
		desc, mime, err := detectFileType(path)
		if err != nil {
			t.Fatalf("detectFileType(%s) error = %v", wantDesc, err)
		}
		if desc != wantDesc {
			t.Fatalf("detectFileType(%s) desc = %q, want %q", wantDesc, desc, wantDesc)
		}
		if mime != wantMime {
			t.Fatalf("detectFileType(%s) mime = %q, want %q", wantDesc, mime, wantMime)
		}
	}

	silverlight := makeZip("sample.xap", map[string]string{
		"AppManifest.xaml": "<Deployment />",
		"AssemblyInfo.cs":  "class X {}",
	})
	checkZip(silverlight, "Microsoft Silverlight Application", "application/x-silverlight-app")

	ooxml := makeZip("sample.accdt", map[string]string{
		"[Content_Types].xml": "<Types/>",
		"_rels/.rels":         "<Relationships/>",
		"docProps/core.xml":   "<cp:coreProperties/>",
	})
	checkZip(ooxml, "Microsoft OOXML", "application/vnd.openxmlformats-officedocument")

	idml := makeZip("sample.idml", map[string]string{
		"designmap.xml":        "<?xml version=\"1.0\"?><Document/>",
		"Stories/Story_u1.xml": "<Story/>",
	})
	checkZip(idml, "Adobe InDesign IDML package", "application/vnd.adobe.indesign-idml-package")

	apk := makeZip("sample.apk", map[string]string{
		"AndroidManifest.xml": "<manifest package=\"example\"/>",
		"classes.dex":         "dex\n035\x00",
	})
	checkZip(apk, "Android application package (APK)", "application/vnd.android.package-archive")

	aab := makeZip("sample.aab", map[string]string{
		"base/manifest/AndroidManifest.xml": "<manifest package=\"example.bundle\"/>",
		"BundleConfig.pb":                   "bundle config",
	})
	checkZip(aab, "Android app bundle (AAB)", "application/vnd.android.appbundle")

	kmz := makeZip("sample.kmz", map[string]string{
		"doc.kml": "<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Placemark/></kml>",
	})
	checkZip(kmz, "KMZ geospatial archive", "application/vnd.google-earth.kmz")

	ipsw := makeZip("sample.ipsw", map[string]string{
		"BuildManifest.plist": "<plist version=\"1.0\"></plist>",
		"Restore.plist":       "<plist version=\"1.0\"></plist>",
	})
	checkZip(ipsw, "Apple IPSW firmware package", "application/x-ipsw")

	jar := makeZip("sample.jar", map[string]string{
		"META-INF/MANIFEST.MF":  "Manifest-Version: 1.0\n",
		"com/example/App.class": "dummy",
	})
	checkZip(jar, "Java JAR archive", "application/java-archive")

	war := makeZip("sample.war", map[string]string{
		"WEB-INF/web.xml":      "<web-app/>",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})
	checkZip(war, "Java WAR archive", "application/java-archive")

	ear := makeZip("sample.ear", map[string]string{
		"META-INF/application.xml": "<application/>",
		"META-INF/MANIFEST.MF":     "Manifest-Version: 1.0\n",
	})
	checkZip(ear, "Java EAR archive", "application/java-archive")

	nupkg := makeZip("sample.nupkg", map[string]string{
		"[Content_Types].xml": "<Types/>",
		"sample.nuspec":       "<package></package>",
	})
	checkZip(nupkg, "NuGet package (NUPKG)", "application/vnd.nuget.package")

	vsix := makeZip("sample.vsix", map[string]string{
		"extension.vsixmanifest": "<PackageManifest/>",
		"[Content_Types].xml":    "<Types/>",
	})
	checkZip(vsix, "Visual Studio extension package (VSIX)", "application/vsix")
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

	desc, mime, err := detectFileType(p)
	if err != nil {
		t.Fatalf("detectFileType(deb) error = %v", err)
	}
	want := "Debian binary package (format 2.0), with control.tar.xz, data compression zst"
	if desc != want {
		t.Fatalf("deb desc = %q, want %q", desc, want)
	}
	if mime != "application/vnd.debian.binary-package" {
		t.Fatalf("deb mime = %q, want %q", mime, "application/vnd.debian.binary-package")
	}
}

func TestDetectFromBytes_GlibcLocalePathFallback(t *testing.T) {
	t.Parallel()

	bin := []byte{0x00, 0x01, 0xB0, 0x7F, 0x00, 0x10}
	got, mime, err := detectFromBytes(bin, "/usr/lib/locale/en_GB.utf8/LC_ADDRESS", nil)
	if err != nil {
		t.Fatalf("detectFromBytes(glibc locale) error = %v", err)
	}
	if got != "glibc locale file LC_ADDRESS" {
		t.Fatalf("detectFromBytes(glibc locale) = %q, want %q", got, "glibc locale file LC_ADDRESS")
	}
	if mime != "application/octet-stream" {
		t.Fatalf("mime(glibc locale) = %q, want %q", mime, "application/octet-stream")
	}
}
