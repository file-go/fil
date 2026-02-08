/*-------------------------------------------------
MIT Licence
Maintainer: Joeky <joeky5888@gmail.com>
--------------------------------------------------*/

package main

import (
	"archive/tar"
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

var activeFile *os.File

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

	for _, filename := range files {
		if filename == "-" && *filesFrom != "" {
			handleStdin(*brief, *mimeOutput, *jsonOutput)
			continue
		}
		processPath(filename, longestFileName, *brief, *mimeOutput, *followSymlinks, *jsonOutput)
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

func processPath(filename string, longestFileName int, brief bool, mimeOutput bool, followSymlinks bool, jsonOutput bool) {
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
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "directory")
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
			printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "directory")
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
	activeFile = file
	defer func() {
		activeFile = nil
	}()
	lenb := len(contentByte)
	if lenb == 0 {
		return "empty", nil
	}
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
	case descLower == "opendocument":
		return "application/vnd.oasis.opendocument"
	case strings.Contains(descLower, "email message (eml)"):
		return "message/rfc822"
	case strings.Contains(descLower, "openvpn configuration"):
		return "application/x-openvpn-profile"
	case strings.Contains(descLower, "apple udif disk image"):
		return "application/x-apple-diskimage"
	case strings.Contains(descLower, "heif image"):
		return "image/heif"
	case strings.Contains(descLower, "m4a audio"):
		return "audio/mp4"
	case strings.Contains(descLower, "ogg opus audio"),
		strings.Contains(descLower, "ogg vorbis audio"),
		strings.Contains(descLower, "ogg flac audio"),
		descLower == "ogg data":
		return "audio/ogg"
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
	case strings.Contains(descLower, "microsoft installer (msi)"):
		return "application/x-msi"
	case strings.Contains(descLower, "sqlite wal file"),
		strings.Contains(descLower, "sqlite journal file"):
		return "application/x-sqlite3"
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

var elfArchByID = map[int]string{
	0x9026: "alpha", 93: "arc", 195: "arcv2", 40: "arm", 183: "arm64",
	0x18ad: "avr32", 247: "bpf", 106: "blackfin", 140: "c6x", 23: "cell",
	76: "cris", 0x5441: "frv", 46: "h8300", 164: "hexagon", 50: "ia64",
	88: "m32r88", 0x9041: "m32r", 4: "m68k", 174: "metag", 189: "microblaze",
	0xbaab: "microblaze-old", 8: "mips", 10: "mips-old", 89: "mn10300",
	0xbeef: "mn10300-old", 113: "nios2", 92: "openrisc", 0x8472: "openrisc-old",
	15: "parisc", 20: "ppc", 21: "ppc64", 22: "s390", 0xa390: "s390-old",
	135: "score", 42: "sh", 2: "sparc", 18: "sparc8+", 43: "sparc9", 188: "tile",
	191: "tilegx", 3: "386", 6: "486", 62: "x86-64", 94: "xtensa", 0xabc7: "xtensa-old",
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

	archj := elfint(contentByte[18:], 2)
	if arch, ok := elfArchByID[archj]; ok {
		output.WriteString(arch)
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
		// Otherwise inspect entries and look for document, workbook, presentation xml, or epub/OpenDocument markers.
		zipReader, err := zip.NewReader(file, info.Size())
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
				// Check for OpenDocument or ePub format
				first200Bytes := make([]byte, 200)
				_, err = file.Read(first200Bytes)
				if err != nil {
					return "Error reading first 200 bytes"
				}
				mimeSample := string(first200Bytes)
				if strings.Contains(mimeSample, "application/vnd.oasis.opendocument.") {
					return "OpenDocument"
				}
				if strings.Contains(mimeSample, "epub") {
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
