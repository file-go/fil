/*-------------------------------------------------
MIT Licence
Maintained by: github.com/presack

Forked from:
Joeky <jj16180339887@gmail.com>

--------------------------------------------------*/

package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	MAX_FILENAME_LENGTH = 256
	MAX_BYTES_TO_READ   = 2 * 1024 // 2KB buffer to read file
)

func main() {
	if len(os.Args) == 1 {
		usage()
	}

	// Expand the wildcard pattern into a list of file names
	files, err := filepath.Glob(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get the length of the longest file name
	longestFileName := 0
	for _, fileName := range files {
		if len(fileName) > longestFileName {
			longestFileName = len(fileName)
		}
	}

	for _, filename := range files {
		fi, err := os.Lstat(filename)
		if err != nil {
			print(filename + ": " + err.Error())
			continue
		}

		if len(filename) > MAX_FILENAME_LENGTH {
			print("File name too long.")
			continue
		}

		print(filename + ": ")
		// Add padding to make columns
		for padding := 0; padding < longestFileName+2-len(filename); padding++ {
			print(" ")
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			reallink, _ := os.Readlink(filename)
			print("symbolic link to " + reallink)
		} else if fi.Mode()&os.ModeDir != 0 {
			print("directory")
		} else if fi.Mode()&os.ModeSocket != 0 {
			print("socket")
		} else if fi.Mode()&os.ModeCharDevice != 0 {
			print("character special device")
		} else if fi.Mode()&os.ModeDevice != 0 {
			print("device file")
		} else if fi.Mode()&os.ModeNamedPipe != 0 {
			print("fifo")
		} else {
			regularFile(filename)
		}
		println()
	}
}

func checkerr(e error) {
	if e != nil {
		print(e.Error())
		os.Exit(1)
	}
}

func usage() {
	println("Usage: fil FILE_NAME")
	os.Exit(0)
}

func regularFile(filename string) {

	/*---------------Read file------------------------*/
	file, _ := os.OpenFile(filename, os.O_RDONLY, 0666)
	// checkerr(err)
	defer file.Close()

	var contentByte = make([]byte, MAX_BYTES_TO_READ)

	numByte, _ := file.Read(contentByte)
	contentByte = contentByte[:numByte]

	lenb := len(contentByte)
	/*---------------Read file end------------------------*/
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	switch {
	case lenb >= 45 && HasPrefix(contentByte, "\x7FELF"):
		print("Elf file ")
		doElf(contentByte)
	case lenb >= 8 && HasPrefix(contentByte, "!<arch>\n"):
		print("ar archive")
	case lenb > 28 && HasPrefix(contentByte, "\x89PNG\x0d\x0a\x1a\x0a"):
		print("PNG image data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "GIF87a") || HasPrefix(contentByte, "GIF89a")):
		print("GIF image data")
	case lenb > 32 && HasPrefix(contentByte, "\xff\xd8"):
		print("JPEG / jpg image data")
	case lenb > 8 && HasPrefix(contentByte, "\xca\xfe\xba\xbe"):
		print("Java class file")
	case lenb > 8 && HasPrefix(contentByte, "dex\n"):
		print("Android dex file")
	case lenb > 500 && Equal(contentByte[257:262], "ustar"):
		print("Posix tar archive")
	case lenb > 5 && HasPrefix(contentByte, "PK\x03\x04"):
		print(doZip(file))
	case lenb > 4 && HasPrefix(contentByte, "BZh"):
		print("bzip2 compressed data")
	case lenb > 10 && HasPrefix(contentByte, "\x1f\x8b"):
		print("gzip compressed data")
	case lenb > 32 && Equal(contentByte[1:4], "\xfa\xed\xfe"):
		print("Mach-O")
	case lenb > 36 && HasPrefix(contentByte, "OggS\x00\x02"):
		print("Ogg data")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:16], "WAVEfmt "):
		print("WAV audio")
	case lenb > 12 && HasPrefix(contentByte, "\x00\x01\x00\x00"):
		print("TrueType font")
	case lenb > 12 && HasPrefix(contentByte, "ttcf\x00"):
		print("TrueType font collection")
	case lenb > 4 && HasPrefix(contentByte, "BC\xc0\xde"):
		print("LLVM IR bitcode")
	case HasPrefix(contentByte, "-----BEGIN CERTIFICATE-----"):
		print("PEM certificate")
	case magic != -1 && HasPrefix(contentByte, "MZ") && magic < lenb-4 &&
		Equal(contentByte[magic:magic+4], "\x50\x45\x00\x00"):

		print("MS executable")
		if peekLe(contentByte[magic+22:], 2)&0x2000 != 0 {
			print("(DLL)")
		}
		print(" ")
		if peekLe(contentByte[magic+20:], 2) > 70 {
			types := []string{"", "native", "GUI", "console", "OS/2", "driver", "CE",
				"EFI", "EFI boot", "EFI runtime", "EFI ROM", "XBOX", "", "boot"}
			tp := peekLe(contentByte[magic+92:], 2)
			if tp > 0 && tp < len(types) {
				print(types[tp])
			}
		}
	case lenb > 50 && HasPrefix(contentByte, "BM") &&
		Equal(contentByte[6:10], "\x00\x00\x00\x00"):
		print("BMP image")
	case lenb > 50 && HasPrefix(contentByte, "\x25\x50\x44\x46"):
		print("PDF image")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x49\x49\x2a\x00") || HasPrefix(contentByte, "\x4D\x4D\x00\x2a")):
		print("TIFF image data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "ID3") || HasPrefix(contentByte, "\xff\xfb") || HasPrefix(contentByte, "\xff\xf3") || HasPrefix(contentByte, "\xff\xf2")):
		print("MP3 audio file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x00\x00\x00\x20\x66\x74\x79\x70") || HasPrefix(contentByte, "\x00\x00\x00\x18\x66\x74\x79\x70") || HasPrefix(contentByte, "\x00\x00\x00\x14\x66\x74\x79\x70")):
		print("MP4 video file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x52\x61\x72\x21\x1A\x07\x01\x00")):
		print("RAR archive data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x37\x7A\xBC\xAF\x27\x1C")):
		print("7zip archive data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x00\x00\x01\x00")):
		print("MS Windows icon resource")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")):
		print("SQLite database")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x0A\x0D\x0D\x0A")):
		print("PCAP-ng capture file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\xD4\xC3\xB2\xA1") || HasPrefix(contentByte, "\xA1\xB2\xC3\xD4") || HasPrefix(contentByte, "\x4D\x3C\xB2\xA1") || HasPrefix(contentByte, "\xA1\xB2\x3C\x4D")):
		print("PCAP capture file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x66\x4C\x61\x43")):
		print("FLAC audio format")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x54\x44\x46\x24")):
		print("Telegram Desktop file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x54\x44\x45\x46")):
		print("Telegram Desktop encrypted file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x4D\x53\x43\x46")):
		print("Microsoft Cabinet file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x38\x42\x50\x53")):
		print("Photoshop document")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:11], "AVI"):
		print("AVI file")
	case lenb > 32 && HasPrefix(contentByte, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
		print("Microsoft Office (Legacy format)")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:12], "WEBP"):
		print("Google Webp file")
	case lenb > 32 && HasPrefix(contentByte, "\x7B\x5C\x72\x74\x66\x31"):
		print("Rich Text Format")
	case lenb > 32 && (HasPrefix(contentByte, "<!DOCTYPE html") || (HasPrefix(contentByte, "<head>"))):
		print("HTML document")
	case lenb > 32 && (HasPrefix(contentByte, "<?xml version")):
		print("XML document")
	}
}

func doElf(contentByte []byte) {
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
		print("relocatable")
	case 2:
		print("executable")
	case 3:
		print("shared object")
	case 4:
		print("core dump")
	default:
		print("bad type")
	}

	print(", ")

	switch bits {
	case 1:
		print("32-bit ")
	case 2:
		print("64-bit ")
	}

	switch endian {
	case 1:
		print("LSB ")
	case 2:
		print("MSB ")
	default:
		print("bad endian ")
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
			print(key)
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
		p_type := elfint(phdr, 4)

		dynamic = (p_type == 2) || dynamic /*PT_DYNAMIC*/
		if p_type != 3 /*PT_INTERP*/ && p_type != 4 /*PT_NOTE*/ {
			continue
		}

		if p_type == 3 /*PT_INTERP*/ {
			print(", dynamically linked")
		}
	}

	if !dynamic {
		print(", statically linked")
	}
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
		ret = ret | int64(c[i])<<uint8(i*8)
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

	info, err := file.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return ("File error")
	}

	// Read the first 60 bytes from the file
	var buf [60]byte
	_, err = file.Read(buf[:])
	if err != nil {
		fmt.Println(err)
		return "File error."
	}

	// Convert the bytes to a string
	str := string(buf[:])

	// Some files have strings in the header indicating the type of Office program or document
	if strings.Contains(str, "word/") && strings.Contains(str, "xml") {
		return "Microsoft Word 2007+"
	} else if strings.Contains(str, "ppt/theme") {
		return "Microsoft PowerPoint 2007+"
	} else if strings.Contains(str, "xl/") && strings.Contains(str, "xml") {
		return "Microsoft Excel 2007+"
		// Otherwise we will loop through looking for document, workbook, or presentation xml files
	} else {

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
			if zipFile.Name == "word/document.xml" {
				return "Microsoft Word 2007+"
			} else if zipFile.Name == "xl/workbook.xml" {
				return "Microsoft Excel 2007+"
			} else if zipFile.Name == "ppt/presentation.xml" {
				return "Microsoft PowerPoint 2007+"
			} else if zipFile.Name == "mimetype" {
				file, err := zipFile.Open()
				if err != nil {
					return "Error opening file"
				}
				defer file.Close()
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
