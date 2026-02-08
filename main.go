/*-------------------------------------------------
MIT Licence
Maintainer: Joeky <joeky5888@gmail.com>
--------------------------------------------------*/

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	MaxFileLength  = 256
	MaxBytesToRead = 36 * 1024 // 36KB buffer to read file (ISO9660 magic starts at 0x8001)
)

type fileMatcher struct {
	name     string
	minLen   int
	match    func([]byte, int, int) bool
	describe func([]byte, int, int, *os.File) string
}

var matchers = []fileMatcher{
	{
		name:   "elf",
		minLen: 45,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 45 && HasPrefix(b, "\x7FELF")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Elf file " + doElf(b)
		},
	},
	{
		name:   "ar",
		minLen: 8,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 8 && HasPrefix(b, "!<arch>\n")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "ar archive"
		},
	},
	{
		name:   "png",
		minLen: 29,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 28 && HasPrefix(b, "\x89PNG\x0d\x0a\x1a\x0a")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "PNG image data"
		},
	},
	{
		name:   "gif",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && (HasPrefix(b, "GIF87a") || HasPrefix(b, "GIF89a"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "GIF image data"
		},
	},
	{
		name:   "jpeg",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "\xff\xd8")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "JPEG / jpg image data"
		},
	},
	{
		name:   "java-class",
		minLen: 9,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 8 && HasPrefix(b, "\xca\xfe\xba\xbe")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Java class file"
		},
	},
	{
		name:   "dex",
		minLen: 9,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 8 && HasPrefix(b, "dex\n")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Android dex file"
		},
	},
	{
		name:   "tar",
		minLen: 501,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 500 && Equal(b[257:262], "ustar")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return doTar(file)
		},
	},
	{
		name:   "zip",
		minLen: 6,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 5 && HasPrefix(b, "PK\x03\x04")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return doZip(file)
		},
	},
	{
		name:   "vmdk",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "KDMV")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "VMware virtual disk"
		},
	},
	{
		name:   "bzip2",
		minLen: 5,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 4 && HasPrefix(b, "BZh")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "bzip2 compressed data"
		},
	},
	{
		name:   "xz",
		minLen: 6,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 6 && HasPrefix(b, "\xFD7zXZ\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "XZ compressed data"
		},
	},
	{
		name:   "zstd",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "\x28\xB5\x2F\xFD")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Zstandard compressed data"
		},
	},
	{
		name:   "lz4",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "\x04\x22\x4D\x18")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "LZ4 compressed data"
		},
	},
	{
		name:   "lzip",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "LZIP")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "LZIP compressed data"
		},
	},
	{
		name:   "gzip",
		minLen: 11,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 10 && HasPrefix(b, "\x1f\x8b")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "gzip compressed data"
		},
	},
	{
		name:   "wasm",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "\x00asm")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "WebAssembly binary"
		},
	},
	{
		name:   "macho",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && Equal(b[1:4], "\xfa\xed\xfe")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Mach-O"
		},
	},
	{
		name:   "flv",
		minLen: 3,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 3 && HasPrefix(b, "FLV")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "FLV video file"
		},
	},
	{
		name:   "matroska",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("matroska"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Matroska video file"
		},
	},
	{
		name:   "webm",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "\x1A\x45\xDF\xA3") && bytes.Contains(b, []byte("webm"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "WebM video file"
		},
	},
	{
		name:   "ogg",
		minLen: 37,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 36 && HasPrefix(b, "OggS\x00\x02")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Ogg data"
		},
	},
	{
		name:   "wav",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:16], "WAVEfmt ")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "WAV audio"
		},
	},
	{
		name:   "woff",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "wOFF")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "WOFF font"
		},
	},
	{
		name:   "woff2",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "wOF2")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "WOFF2 font"
		},
	},
	{
		name:   "ttf",
		minLen: 13,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 12 && HasPrefix(b, "\x00\x01\x00\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "TrueType font"
		},
	},
	{
		name:   "ttf-collection",
		minLen: 13,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 12 && HasPrefix(b, "ttcf\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "TrueType font collection"
		},
	},
	{
		name:   "llvm-bitcode",
		minLen: 5,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 4 && HasPrefix(b, "BC\xc0\xde")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "LLVM IR bitcode"
		},
	},
	{
		name:   "parquet",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "PAR1")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Parquet data"
		},
	},
	{
		name:   "avro",
		minLen: 4,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 4 && HasPrefix(b, "Obj\x01")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Avro data"
		},
	},
	{
		name:   "pem",
		minLen: len("-----BEGIN CERTIFICATE-----"),
		match: func(b []byte, lenb int, magic int) bool {
			return HasPrefix(b, "-----BEGIN CERTIFICATE-----")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "PEM certificate"
		},
	},
	{
		name:   "pe",
		minLen: 64,
		match: func(b []byte, lenb int, magic int) bool {
			return magic != -1 && HasPrefix(b, "MZ") && magic < lenb-4 &&
				Equal(b[magic:magic+4], "\x50\x45\x00\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return describePE(b, magic)
		},
	},
	{
		name:   "iso9660",
		minLen: 0x8006,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb >= 0x8006 && Equal(b[0x8001:0x8006], "CD001")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "ISO 9660 CD-ROM filesystem"
		},
	},
	{
		name:   "bmp",
		minLen: 51,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 50 && HasPrefix(b, "BM") && Equal(b[6:10], "\x00\x00\x00\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "BMP image"
		},
	},
	{
		name:   "pdf",
		minLen: 51,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 50 && HasPrefix(b, "\x25\x50\x44\x46")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "PDF image"
		},
	},
	{
		name:   "tiff",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 &&
				(HasPrefix(b, "\x49\x49\x2a\x00") || HasPrefix(b, "\x4D\x4D\x00\x2a"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "TIFF image data"
		},
	},
	{
		name:   "mp3",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 &&
				(HasPrefix(b, "ID3") || HasPrefix(b, "\xff\xfb") || HasPrefix(b, "\xff\xf3") || HasPrefix(b, "\xff\xf2"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "MP3 audio file"
		},
	},
	{
		name:   "mp4",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 &&
				(HasPrefix(b, "\x00\x00\x00\x20\x66\x74\x79\x70") || HasPrefix(b, "\x00\x00\x00\x18\x66\x74\x79\x70") || HasPrefix(b, "\x00\x00\x00\x14\x66\x74\x79\x70"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "MP4 video file"
		},
	},
	{
		name:   "rar",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x52\x61\x72\x21\x1A\x07\x01\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "RAR archive data"
		},
	},
	{
		name:   "7zip",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x37\x7A\xBC\xAF\x27\x1C")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "7zip archive data"
		},
	},
	{
		name:   "ico",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x00\x00\x01\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "MS Windows icon resource"
		},
	},
	{
		name:   "sqlite",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "SQLite database"
		},
	},
	{
		name:   "pcapng",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x0A\x0D\x0D\x0A")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "PCAP-ng capture file"
		},
	},
	{
		name:   "pcap",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 &&
				(HasPrefix(b, "\xD4\xC3\xB2\xA1") || HasPrefix(b, "\xA1\xB2\xC3\xD4") || HasPrefix(b, "\x4D\x3C\xB2\xA1") || HasPrefix(b, "\xA1\xB2\x3C\x4D"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "PCAP capture file"
		},
	},
	{
		name:   "flac",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x66\x4C\x61\x43")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "FLAC audio format"
		},
	},
	{
		name:   "tdf",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x54\x44\x46\x24")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Telegram Desktop file"
		},
	},
	{
		name:   "tdef",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x54\x44\x45\x46")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Telegram Desktop encrypted file"
		},
	},
	{
		name:   "cab",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x4D\x53\x43\x46")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Microsoft Cabinet file"
		},
	},
	{
		name:   "psd",
		minLen: 17,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 16 && HasPrefix(b, "\x38\x42\x50\x53")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Photoshop document"
		},
	},
	{
		name:   "avi",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:11], "AVI")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "AVI file"
		},
	},
	{
		name:   "ole",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Microsoft Office (Legacy format)"
		},
	},
	{
		name:   "webp",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "RIF") && Equal(b[8:12], "WEBP")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Google Webp file"
		},
	},
	{
		name:   "rtf",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "\x7B\x5C\x72\x74\x66\x31")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "Rich Text Format"
		},
	},
	{
		name:   "html",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && (HasPrefix(b, "<!DOCTYPE html") || HasPrefix(b, "<head>"))
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "HTML document"
		},
	},
	{
		name:   "xml",
		minLen: 33,
		match: func(b []byte, lenb int, magic int) bool {
			return lenb > 32 && HasPrefix(b, "<?xml version")
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return "XML document"
		},
	},
	{
		name:   "text",
		minLen: 1,
		match: func(b []byte, lenb int, magic int) bool {
			return isText(b)
		},
		describe: func(b []byte, lenb int, magic int, file *os.File) string {
			return describeText(b)
		},
	},
}

func main() {
	brief := flag.Bool("b", false, "brief output (type only)")
	followSymlinks := flag.Bool("L", false, "follow symlinks")
	mimeOutput := flag.Bool("i", false, "MIME type output")
	jsonOutput := flag.Bool("json", false, "JSONL output")
	filesFrom := flag.String("files-from", "", "read file paths from a file ('-' for stdin)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
	}

	var files []string
	if *filesFrom != "" {
		list, err := readFilesFrom(*filesFrom)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		files = list
	} else {
		// Expand the wildcard pattern into a list of file names
		if flag.Arg(0) == "-" {
			handleStdin(*brief, *mimeOutput, *jsonOutput)
			return
		}
		var err error
		files, err = filepath.Glob(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	// Get the length of the longest file name
	longestFileName := 0
	for _, fileName := range files {
		if len(fileName) > longestFileName {
			longestFileName = len(fileName)
		}
	}

	visitedDirs := make(map[string]struct{})
	for _, filename := range files {
		if filename == "-" && *filesFrom != "" {
			handleStdin(*brief, *mimeOutput, *jsonOutput)
			continue
		}
		processPath(filename, longestFileName, *brief, *mimeOutput, *followSymlinks, *jsonOutput, visitedDirs)
	}
}

func usage() {
	fmt.Println("Usage: fil [-b] [-i] [-L] [--json] [--files-from=PATH] FILE_NAME")
	fmt.Println("       fil -")
	fmt.Println("  -b    brief output (type only)")
	fmt.Println("  -i    MIME type output")
	fmt.Println("  -L    follow symlinks")
	fmt.Println("  --json JSONL output")
	fmt.Println("  --files-from=PATH read file paths from a file ('-' for stdin)")
	os.Exit(0)
}

func processPath(filename string, longestFileName int, brief bool, mimeOutput bool, followSymlinks bool, jsonOutput bool, visitedDirs map[string]struct{}) {
	fi, err := os.Lstat(filename)
	if err != nil {
		emitError(filename, err, jsonOutput)
		return
	}

	if len(filename) > MaxFileLength {
		emitError(filename, fmt.Errorf("file name too long"), jsonOutput)
		return
	}

	if fi.Mode().IsDir() {
		realPath := filename
		if followSymlinks {
			if resolved, err := filepath.EvalSymlinks(filename); err == nil {
				realPath = resolved
			}
		}
		if _, seen := visitedDirs[realPath]; seen {
			return
		}
		visitedDirs[realPath] = struct{}{}
		filepath.WalkDir(realPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				emitError(path, err, jsonOutput)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 && followSymlinks {
				target, err := filepath.EvalSymlinks(path)
				if err != nil {
					emitError(path, err, jsonOutput)
					return nil
				}
				tinfo, err := os.Stat(target)
				if err != nil {
					emitError(path, err, jsonOutput)
					return nil
				}
				if tinfo.IsDir() {
					return nil
				}
				desc, derr := detectFileType(target)
				if derr != nil {
					emitError(path, derr, jsonOutput)
					return nil
				}
				printResult(path, longestFileName, brief, mimeOutput, jsonOutput, desc)
				return nil
			}
			if d.Type().IsRegular() {
				desc, derr := detectFileType(path)
				if derr != nil {
					emitError(path, derr, jsonOutput)
					return nil
				}
				printResult(path, longestFileName, brief, mimeOutput, jsonOutput, desc)
			}
			return nil
		})
		return
	}

	if fi.Mode()&os.ModeSymlink != 0 && followSymlinks {
		target, err := filepath.EvalSymlinks(filename)
		if err != nil {
			emitError(filename, err, jsonOutput)
			return
		}
		tinfo, err := os.Stat(target)
		if err != nil {
			emitError(filename, err, jsonOutput)
			return
		}
		if tinfo.IsDir() {
			processPath(target, longestFileName, brief, mimeOutput, followSymlinks, jsonOutput, visitedDirs)
			return
		}
		desc, derr := detectFileType(target)
		if derr != nil {
			emitError(filename, derr, jsonOutput)
			return
		}
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, desc)
		return
	}

	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		reallink, _ := os.Readlink(filename)
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "symbolic link to "+reallink)
	case fi.Mode()&os.ModeSocket != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "socket")
	case fi.Mode()&os.ModeCharDevice != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "character special device")
	case fi.Mode()&os.ModeDevice != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "device file")
	case fi.Mode()&os.ModeNamedPipe != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "fifo")
	default:
		desc, derr := detectFileType(filename)
		if derr != nil {
			emitError(filename, derr, jsonOutput)
			return
		}
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, desc)
	}
}

func printResult(filename string, longestFileName int, brief bool, mimeOutput bool, jsonOutput bool, desc string) {
	if desc == "" {
		return
	}
	if jsonOutput {
		emitJSON(filename, desc, mimeOutput, "")
		return
	}
	if mimeOutput {
		desc = mimeForDescription(desc)
	}
	if !brief {
		fmt.Print(filename + ": ")
		for padding := 0; padding < longestFileName+2-len(filename); padding++ {
			fmt.Print(" ")
		}
	}
	fmt.Println(desc)
}

type jsonLine struct {
	Path  string `json:"path"`
	Type  string `json:"type,omitempty"`
	Mime  string `json:"mime,omitempty"`
	Error string `json:"error,omitempty"`
}

func emitJSON(path string, desc string, mimeOutput bool, errMsg string) {
	out := jsonLine{
		Path:  path,
		Type:  desc,
		Error: errMsg,
	}
	if mimeOutput {
		out.Mime = mimeForDescription(desc)
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, path+": "+err.Error())
		return
	}
	fmt.Println(string(b))
}

func emitError(path string, err error, jsonOutput bool) {
	fmt.Fprintln(os.Stderr, path+": "+err.Error())
	if jsonOutput {
		emitJSON(path, "", false, err.Error())
	}
}

func detectFileType(filename string) (string, error) {

	/*---------------Read file------------------------*/
	file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var contentByte = make([]byte, MaxBytesToRead)

	numByte, err := file.Read(contentByte)
	if err != nil && err != io.EOF {
		return "", err
	}
	contentByte = contentByte[:numByte]

	return detectFromBytes(contentByte, filename, file)
}

func detectFromBytes(contentByte []byte, filename string, file *os.File) (string, error) {
	lenb := len(contentByte)
	/*---------------Read file end------------------------*/
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	for _, matcher := range matchers {
		if lenb >= matcher.minLen && matcher.match(contentByte, lenb, magic) {
			return matcher.describe(contentByte, lenb, magic, file), nil
		}
	}
	return "", nil
}

func handleStdin(brief bool, mimeOutput bool, jsonOutput bool) {
	buf := make([]byte, MaxBytesToRead)
	n := 0
	for n < len(buf) {
		readN, err := os.Stdin.Read(buf[n:])
		if readN > 0 {
			n += readN
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			emitError("stdin", err, jsonOutput)
			return
		}
	}
	desc, derr := detectFromBytes(buf[:n], "stdin", nil)
	if derr != nil {
		emitError("stdin", derr, jsonOutput)
		return
	}
	printResult("stdin", 0, brief, mimeOutput, jsonOutput, desc)
}

func readFilesFrom(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func mimeForDescription(desc string) string {
	descLower := strings.ToLower(desc)

	switch {
	case descLower == "directory":
		return "inode/directory"
	case strings.HasPrefix(descLower, "symbolic link to "):
		return "inode/symlink"
	case descLower == "png image data":
		return "image/png"
	case descLower == "gif image data":
		return "image/gif"
	case strings.HasPrefix(descLower, "jpeg / jpg image data"):
		return "image/jpeg"
	case descLower == "pdf image":
		return "application/pdf"
	case strings.Contains(descLower, "zip archive"):
		return "application/zip"
	case strings.Contains(descLower, "posix tar archive"):
		return "application/x-tar"
	case strings.Contains(descLower, "gzip compressed data"):
		return "application/gzip"
	case strings.Contains(descLower, "bzip2 compressed data"):
		return "application/x-bzip2"
	case strings.Contains(descLower, "xz compressed data"):
		return "application/x-xz"
	case strings.Contains(descLower, "zstandard compressed data"):
		return "application/zstd"
	case strings.Contains(descLower, "lz4 compressed data"):
		return "application/x-lz4"
	case strings.Contains(descLower, "lzip compressed data"):
		return "application/x-lzip"
	case strings.Contains(descLower, "rar archive data"):
		return "application/vnd.rar"
	case strings.Contains(descLower, "7zip archive data"):
		return "application/x-7z-compressed"
	case strings.Contains(descLower, "microsoft word 2007+"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case strings.Contains(descLower, "microsoft excel 2007+"):
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case strings.Contains(descLower, "microsoft powerpoint 2007+"):
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case strings.Contains(descLower, "epub document"):
		return "application/epub+zip"
	case strings.Contains(descLower, "email message (eml)"):
		return "message/rfc822"
	case strings.Contains(descLower, "openvpn configuration"):
		return "application/x-openvpn-profile"
	case strings.Contains(descLower, "vmware ova appliance"):
		return "application/x-virtualbox-ova"
	case strings.Contains(descLower, "vmware virtual disk"):
		return "application/x-vmdk"
	case strings.Contains(descLower, "vmware snapshot state"):
		return "application/x-vmware-vmsn"
	case strings.Contains(descLower, "vmware vm configuration"):
		return "text/plain"
	case strings.Contains(descLower, "vmware supplemental configuration"):
		return "text/plain"
	}

	return "application/octet-stream"
}

func isText(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	badCtrl := 0
	for _, c := range b {
		if c == 0x00 {
			return false
		}
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\f' && c != '\b' {
			badCtrl++
		}
	}

	if badCtrl > 0 && badCtrl*100/len(b) > 2 {
		return false
	}

	if isASCIIOnly(b) {
		return true
	}
	return utf8.Valid(b)
}

func isASCIIOnly(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func describeText(b []byte) string {
	base := "UTF-8 text"
	if isASCIIOnly(b) {
		base = "ASCII text"
	}

	subtype := detectTextSubtype(b)
	if subtype != "" {
		return base + ", " + subtype
	}
	return base
}

func detectTextSubtype(b []byte) string {
	const maxScan = 32 * 1024
	end := len(b)
	if end > maxScan {
		end = maxScan
	}

	top := string(b[:end])
	topLower := strings.ToLower(top)
	topLower = "\n" + topLower

	if hasAll(topLower, "\nfrom:", "\nto:", "\nsubject:", "\ndate:") {
		return "email"
	}

	if looksLikeOpenVPN(topLower) {
		return "OpenVPN config"
	}

	if strings.HasPrefix(top, "#!/bin/sh") || strings.HasPrefix(top, "#!/bin/bash") {
		return "shell script"
	}

	if strings.HasPrefix(top, "#!/usr/bin/python") || strings.HasPrefix(top, "#!/usr/bin/env python") {
		return "Python script"
	}

	if strings.Contains(topLower, "\n#requires") || strings.Contains(topLower, "\nparam(") || strings.Contains(topLower, "$psversiontable") {
		return "PowerShell script"
	}

	if looksLikeJavaScript(topLower) {
		return "JavaScript"
	}

	return ""
}

func hasAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func looksLikeOpenVPN(s string) bool {
	hits := 0
	if strings.Contains(s, "\nclient") {
		hits++
	}
	if strings.Contains(s, "\ndev ") {
		hits++
	}
	if strings.Contains(s, "\nproto ") {
		hits++
	}
	if strings.Contains(s, "\nremote ") {
		hits++
	}
	return hits >= 2
}

func looksLikeJavaScript(s string) bool {
	hits := 0
	if strings.Contains(s, "function ") || strings.Contains(s, "\nfunction ") {
		hits++
	}
	if strings.Contains(s, "const ") || strings.Contains(s, "\nconst ") {
		hits++
	}
	if strings.Contains(s, "import ") || strings.Contains(s, "\nimport ") {
		hits++
	}
	if strings.Contains(s, "export ") || strings.Contains(s, "\nexport ") {
		hits++
	}
	return hits >= 2
}

func doElf(contentByte []byte) string {
	var output strings.Builder
	bits := int(contentByte[4])
	endian := contentByte[5]

	var elfint func(c []byte, size int) int

	if endian == 2 {
		elfint = peekBe
	} else {
		elfint = peekLe
	}

	exei := elfint(contentByte[16:], 2)

	switch exei {
	case 1:
		output.WriteString("relocatable")
	case 2:
		output.WriteString("executable")
	case 3:
		output.WriteString("shared object")
	case 4:
		output.WriteString("core dump")
	default:
		output.WriteString("bad type")
	}

	output.WriteString(", ")

	switch bits {
	case 1:
		output.WriteString("32-bit ")
	case 2:
		output.WriteString("64-bit ")
	}

	switch endian {
	case 1:
		output.WriteString("LSB ")
	case 2:
		output.WriteString("MSB ")
	default:
		output.WriteString("bad endian ")
	}

	/* You can have a full list from here https://golang.org/src/debug/elf/elf.go */
	archType := map[string]int{
		"alpha": 0x9026, "arc": 93, "arcv2": 195, "arm": 40, "arm64": 183,
		"avr32": 0x18ad, "bpf": 247, "blackfin": 106, "c6x": 140, "cell": 23,
		"cris": 76, "frv": 0x5441, "h8300": 46, "hexagon": 164, "ia64": 50,
		"m32r88": 88, "m32r": 0x9041, "m68k": 4, "metag": 174, "microblaze": 189,
		"microblaze-old": 0xbaab, "mips": 8, "mips-old": 10, "mn10300": 89,
		"mn10300-old": 0xbeef, "nios2": 113, "openrisc": 92, "openrisc-old": 0x8472,
		"parisc": 15, "ppc": 20, "ppc64": 21, "s390": 22, "s390-old": 0xa390,
		"score": 135, "sh": 42, "sparc": 2, "sparc8+": 18, "sparc9": 43, "tile": 188,
		"tilegx": 191, "386": 3, "486": 6, "x86-64": 62, "xtensa": 94, "xtensa-old": 0xabc7,
	}

	archj := elfint(contentByte[18:], 2)
	for key, val := range archType {
		if val == archj {
			output.WriteString(key)
			break
		}
	}

	bits--

	phentsize := elfint(contentByte[42+12*bits:], 2)
	phnum := elfint(contentByte[44+12*bits:], 2)
	phoff := elfint(contentByte[28+4*bits:], 4+4*bits)

	dynamic := false

	for i := 0; i < phnum; i++ {
		phdr := contentByte[phoff+i*phentsize:]
		ptpye := elfint(phdr, 4)

		dynamic = (ptpye == 2) || dynamic /*PT_DYNAMIC*/
		if ptpye != 3 /*PT_INTERP*/ && ptpye != 4 /*PT_NOTE*/ {
			continue
		}

		if ptpye == 3 /*PT_INTERP*/ {
			output.WriteString(", dynamically linked")
		}
	}

	if !dynamic {
		output.WriteString(", statically linked")
	}

	return output.String()
}

func HasPrefix(s []byte, prefix string) bool {
	return len(s) >= len(prefix) && Equal(s[:len(prefix)], prefix)
}

func Equal(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range []byte(b) {
		if v != a[i] {
			return false
		}
	}
	return true
}

func peekLe(c []byte, size int) int {
	ret := int64(0)

	for i := 0; i < size; i++ {
		ret |= int64(c[i]) << uint8(i*8)
	}
	return int(ret)
}

func peekBe(c []byte, size int) int {
	ret := int64(0)

	for i := 0; i < size; i++ {
		ret = (ret << 8) | (int64(c[i]) & 0xff)
	}
	return int(ret)
}

func doZip(file *os.File) string {
	// Function distinguishes between Office XML documents and regular zip files.
	// First read the intial bytes of the file, and see if common Word, Excel, Powerpoint strings are present.
	// Next, there are some other strings that seem to appear in Office documents of multiple types; For these,
	// we will open the zip real quick and look for the Word, Excel, PowerPoint xml file, or epub mimetype file. Otherwise it is a regular zip.

	if file == nil {
		return "Zip archive data"
	}

	if _, err := file.Seek(0, 0); err != nil {
		return "File error"
	}

	info, err := file.Stat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting file info:", err)
		return ("File error")
	}

	// Read the first 60 bytes from the file
	var buf [60]byte
	n, err := file.Read(buf[:])
	if err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, err)
		return "File error."
	}

	// Convert the bytes to a string
	str := string(buf[:n])

	// Some files have strings in the header indicating the type of Office program or document
	switch {
	case strings.Contains(str, "word/") && strings.Contains(str, "xml"):
		return "Microsoft Word 2007+"
	case strings.Contains(str, "ppt/theme"):
		return "Microsoft PowerPoint 2007+"
	case strings.Contains(str, "xl/") && strings.Contains(str, "xml"):
		return "Microsoft Excel 2007+"
	default:
		// Otherwise we will open zip and look for document, workbook, or presentation xml files
		f, err := os.Open(file.Name())
		if err != nil {
			return "Error opening file"
		}
		defer f.Close()

		// Check if the file is a ZIP archive
		zipReader, err := zip.NewReader(f, info.Size())
		if err != nil {
			return "Unknown file type"
		}
		// Loop through the files in the ZIP archive
		for _, zipFile := range zipReader.File {
			switch zipFile.Name {
			case "word/document.xml":
				return "Microsoft Word 2007+"
			case "xl/workbook.xml":
				return "Microsoft Excel 2007+"
			case "ppt/presentation.xml":
				return "Microsoft PowerPoint 2007+"
			case "mimetype":
				file, err := zipFile.Open()
				if err != nil {
					return "Error opening file"
				}
				defer file.Close()
				// Check for ePub format
				first20Bytes := make([]byte, 20)
				_, err = file.Read(first20Bytes)
				if err != nil {
					return "Error reading first 20 bytes"
				}
				if strings.Contains(string(first20Bytes), "epub") {
					return "EPUB document"
				}
			}
		}
	}

	return "Zip archive data"
}

func doTar(file *os.File) string {
	// OVA is a tar containing at least one .ovf descriptor file.
	if file == nil {
		return "Posix tar archive"
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "Posix tar archive"
	}

	tr := tar.NewReader(file)
	const maxEntries = 200
	for i := 0; i < maxEntries; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "Posix tar archive"
		}
		if strings.HasSuffix(strings.ToLower(hdr.Name), ".ovf") {
			return "VMware OVA appliance"
		}
	}

	return "Posix tar archive"
}

func describePE(contentByte []byte, magic int) string {
	var output strings.Builder

	// Linux kernel images look like PE files.
	if Equal(contentByte[56:60], "ARMd") {
		return "Linux arm64 kernel image"
	}
	if Equal(contentByte[514:518], "HdrS") {
		return "Linux x86-64 kernel image"
	}

	output.WriteString("MS PE32")
	if peekLe(contentByte[magic+24:], 2) == 0x20b {
		output.WriteString("+")
	}
	output.WriteString(" executable")
	if peekLe(contentByte[magic+22:], 2)&0x2000 != 0 {
		output.WriteString("(DLL)")
	}
	output.WriteString(" ")
	if peekLe(contentByte[magic+20:], 2) > 70 {
		types := []string{"", "native", "GUI", "console", "OS/2", "driver", "CE",
			"EFI", "EFI boot", "EFI runtime", "EFI ROM", "XBOX", "", "boot"}
		tp := peekLe(contentByte[magic+92:], 2)
		if tp > 0 && tp < len(types) {
			output.WriteString(types[tp])
		} else {
			output.WriteString("unknown")
		}
	}

	// Ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	switch peekLe(contentByte[magic+4:], 2) {
	case 0x1c0:
		output.WriteString(" arm")
	case 0xaa64:
		output.WriteString(" aarch64")
	case 0x14c:
		output.WriteString(" Intel 80386")
	case 0x8664:
		output.WriteString(" amd64")
	}

	return output.String()
}
