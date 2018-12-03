/*-------------------------------------------------
MIT Licence

Maintainer: Joeky <jj16180339887@gmail.com>
--------------------------------------------------*/

package main

import (
	"os"
)

const (
	MAX_FILENAME_LENGTH = 256
	MAX_BYTES_TO_READ   = 2 * 1024 // 2KB buffer to read file
)

func main() {
	if len(os.Args) == 1 {
		usage()
	}

	for _, filename := range os.Args[1:] {
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
			// } else if fi.Mode()&os.ModeIrregular == 0 {
			// 	regularFile(filename)
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
	// if err != nil && err != io.EOF {
	// 	checkerr(err)
	// }
	contentByte = contentByte[:numByte]

	lenb := len(contentByte)
	/*---------------Read file end------------------------*/
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	if lenb >= 45 && HasPrefix(contentByte, "\x7FELF") {
		print("Elf file ")
		doElf(contentByte)
	} else if lenb >= 8 && HasPrefix(contentByte, "!<arch>\n") {
		print("ar archive")
	} else if lenb > 28 && HasPrefix(contentByte, "\x89PNG\x0d\x0a\x1a\x0a") {
		print("PNG image data")
	} else if lenb > 16 &&
		(HasPrefix(contentByte, "GIF87a") || HasPrefix(contentByte, "GIF89a")) {
		print("GIF image data")
	} else if lenb > 32 && HasPrefix(contentByte, "\xff\xd8") {
		print("JPEG image data")
	} else if lenb > 8 && HasPrefix(contentByte, "\xca\xfe\xba\xbe") {
		print("Java class file")
	} else if lenb > 8 && HasPrefix(contentByte, "dex\n") {
		print("Android dex file")
	} else if lenb > 500 && Equal(contentByte[257:262], "ustar") {
		print("Posix tar archive")
	} else if lenb > 5 && HasPrefix(contentByte, "PK\x03\x04") {
		print("Zip archive data")
	} else if lenb > 4 && HasPrefix(contentByte, "BZh") {
		print("bzip2 compressed data")
	} else if lenb > 10 && HasPrefix(contentByte, "\x1f\x8b") {
		print("gzip compressed data")
	} else if lenb > 32 && Equal(contentByte[1:4], "\xfa\xed\xfe") {
		print("Mach-O")
	} else if lenb > 36 && HasPrefix(contentByte, "OggS\x00\x02") {
		print("Ogg data")
	} else if lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:16], "WAVEfmt ") {
		print("WAV audio")
	} else if lenb > 12 && HasPrefix(contentByte, "\x00\x01\x00\x00") {
		print("TrueType font")
	} else if lenb > 12 && HasPrefix(contentByte, "ttcf\x00") {
		print("TrueType font collection")
	} else if lenb > 4 && HasPrefix(contentByte, "BC\xc0\xde") {
		print("LLVM IR bitcode")
	} else if HasPrefix(contentByte, "-----BEGIN CERTIFICATE-----") {
		print("PEM certificate")
	} else if magic != -1 && HasPrefix(contentByte, "MZ") && magic < lenb-4 &&
		Equal(contentByte[magic:magic+4], "\x50\x45\x00\x00") {

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
	} else if lenb > 50 && HasPrefix(contentByte, "BM") &&
		Equal(contentByte[6:10], "\x00\x00\x00\x00") {
		print("BMP image")
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
		print("32bit ")
	case 2:
		print("64bit ")
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
	// shsize 		:= elfint(contentByte[46+12*bits:], 2)
	// shnum 		:= elfint(contentByte[48+12*bits:], 2)
	// shoff 		:= elfint(contentByte[32+8*bits:], 4+4*bits)
	dynamic := false

	for i := 0; i < phnum; i++ {
		phdr := contentByte[phoff+i*phentsize:]
		// char *phdr = map+phoff+i*phentsize;
		p_type := elfint(phdr, 4)

		dynamic = (p_type == 2) || dynamic /*PT_DYNAMIC*/
		if p_type != 3 /*PT_INTERP*/ && p_type != 4 /*PT_NOTE*/ {
			continue
		}

		// j = bits+1
		// p_offset := elfint(phdr[4*j:], 4*j)
		// p_filesz := elfint(phdr[16*j:], 4*j)

		if p_type == 3 /*PT_INTERP*/ {
			print(", dynamically linked")
			//   print(p_filesz)
			//   print(contentByte[p_offset*2:])
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
