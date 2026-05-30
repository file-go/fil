/*-------------------------------------------------
MIT Licence
Maintainer: Joeky <joeky5888@gmail.com>
--------------------------------------------------*/

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxFileLength  = 256
	MaxBytesToRead = 36 * 1024 // 36KB buffer to read file (ISO9660 magic starts at 0x8001)
)

type fileMatcher struct {
	name     string
	minLen   int
	mime     string
	match    func([]byte, int, int, *os.File) bool
	describe func([]byte, int, int, *os.File) string
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
		// Expand each argument as a glob pattern and collect results.
		for _, arg := range flag.Args() {
			if arg == "-" {
				handleStdin(*brief, *mimeOutput, *jsonOutput)
				continue
			}
			expanded, err := filepath.Glob(arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			files = append(files, expanded...)
		}
	}

	// Get the length of the longest file name for column alignment.
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
	fmt.Println("Usage: fil [-b] [-i] [-L] [--json] [--files-from=PATH] FILE [FILE ...]")
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
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "directory", "")
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
			printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "directory", "")
			return
		}
		desc, mime, derr := detectFileType(target)
		if derr != nil {
			emitError(filename, derr, jsonOutput)
			return
		}
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, desc, mime)
		return
	}

	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		reallink, _ := os.Readlink(filename)
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "symbolic link to "+reallink, "")
	case fi.Mode()&os.ModeSocket != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "socket", "")
	case fi.Mode()&os.ModeCharDevice != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "character special device", "")
	case fi.Mode()&os.ModeDevice != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "device file", "")
	case fi.Mode()&os.ModeNamedPipe != 0:
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, "fifo", "")
	default:
		desc, mime, derr := detectFileType(filename)
		if derr != nil {
			emitError(filename, derr, jsonOutput)
			return
		}
		printResult(filename, longestFileName, brief, mimeOutput, jsonOutput, desc, mime)
	}
}

func printResult(filename string, longestFileName int, brief bool, mimeOutput bool, jsonOutput bool, desc, mime string) {
	if desc == "" {
		return
	}
	if jsonOutput {
		emitJSON(filename, desc, mimeOutput, mime, "")
		return
	}
	if mimeOutput {
		if mime == "" {
			mime = dynamicMIME(desc)
		}
		desc = mime
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

func emitJSON(path string, desc string, mimeOutput bool, mime string, errMsg string) {
	out := jsonLine{
		Path:  path,
		Type:  desc,
		Error: errMsg,
	}
	if mimeOutput {
		if mime == "" {
			mime = dynamicMIME(desc)
		}
		out.Mime = mime
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
		emitJSON(path, "", false, "", err.Error())
	}
}

func detectFileType(filename string) (string, string, error) {

	/*---------------Read file------------------------*/
	file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	var contentByte = make([]byte, MaxBytesToRead)

	numByte, err := file.Read(contentByte)
	if err != nil && err != io.EOF {
		return "", "", err
	}
	contentByte = contentByte[:numByte]

	return detectFromBytes(contentByte, filename, file)
}

func detectFromBytes(contentByte []byte, filename string, file *os.File) (string, string, error) {
	lenb := len(contentByte)
	if lenb == 0 {
		return "empty", "application/octet-stream", nil
	}
	/*---------------Read file end------------------------*/
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	for _, matcher := range matchers {
		if lenb >= matcher.minLen && matcher.match(contentByte, lenb, magic, file) {
			if matcher.name == "data" {
				if desc := glibcLocaleDescriptionForPath(filename, contentByte); desc != "" {
					return desc, "application/octet-stream", nil
				}
			}
			desc := matcher.describe(contentByte, lenb, magic, file)
			mime := matcher.mime
			if mime == "" {
				mime = dynamicMIME(desc)
			}
			return desc, mime, nil
		}
	}
	return "", "application/octet-stream", nil
}

func glibcLocaleDescriptionForPath(filename string, b []byte) string {
	if filename == "" || isText(b) {
		return ""
	}
	p := strings.ToLower(strings.ReplaceAll(filename, "\\", "/"))
	if !strings.Contains(p, "/usr/lib/locale/") {
		return ""
	}

	base := strings.ToLower(path.Base(p))
	category := ""
	switch {
	case base == "sys_lc_messages":
		category = "LC_MESSAGES"
	case strings.HasPrefix(base, "lc_"):
		candidate := strings.ToUpper(base)
		if isKnownLocaleCategory(candidate) {
			category = candidate
		}
	}
	if category == "" {
		return ""
	}
	return "glibc locale file " + category
}

func isKnownLocaleCategory(s string) bool {
	switch s {
	case "LC_ADDRESS", "LC_COLLATE", "LC_CTYPE", "LC_IDENTIFICATION", "LC_MEASUREMENT",
		"LC_MESSAGES", "LC_MONETARY", "LC_NAME", "LC_NUMERIC", "LC_PAPER", "LC_TELEPHONE", "LC_TIME":
		return true
	default:
		return false
	}
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
	desc, mime, derr := detectFromBytes(buf[:n], "stdin", nil)
	if derr != nil {
		emitError("stdin", derr, jsonOutput)
		return
	}
	printResult("stdin", 0, brief, mimeOutput, jsonOutput, desc, mime)
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

// dynamicMIME resolves MIME types for matchers whose describe functions return
// varying strings (zip sub-types, tar, ar, text, pem, 3gpp, xml) and for
// OS-level descriptors (directory, symlink) that bypass the matcher registry.
// All matchers with static descriptions use the mime field instead.
func dynamicMIME(desc string) string {
	dl := strings.ToLower(desc)

	switch {
	// OS-level types
	case dl == "directory":
		return "inode/directory"
	case strings.HasPrefix(dl, "symbolic link to "):
		return "inode/symlink"

	// ZIP sub-types (doZip returns many different descriptions)
	case strings.Contains(dl, "microsoft word 2007+"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case strings.Contains(dl, "microsoft excel 2007+"):
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case strings.Contains(dl, "microsoft powerpoint 2007+"):
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case strings.Contains(dl, "microsoft ooxml"):
		return "application/vnd.openxmlformats-officedocument"
	case strings.Contains(dl, "microsoft silverlight application"):
		return "application/x-silverlight-app"
	case strings.Contains(dl, "adobe indesign idml package"):
		return "application/vnd.adobe.indesign-idml-package"
	case strings.Contains(dl, "android application package (apk)"):
		return "application/vnd.android.package-archive"
	case strings.Contains(dl, "android app bundle (aab)"):
		return "application/vnd.android.appbundle"
	case strings.Contains(dl, "kmz geospatial archive"):
		return "application/vnd.google-earth.kmz"
	case strings.Contains(dl, "apple ipsw firmware package"):
		return "application/x-ipsw"
	case strings.Contains(dl, "visual studio extension package (vsix)"):
		return "application/vsix"
	case strings.Contains(dl, "nuget package (nupkg)"):
		return "application/vnd.nuget.package"
	case strings.Contains(dl, "java war archive"), strings.Contains(dl, "java ear archive"), strings.Contains(dl, "java jar archive"):
		return "application/java-archive"
	case strings.Contains(dl, "epub document"):
		return "application/epub+zip"
	case dl == "opendocument text":
		return "application/vnd.oasis.opendocument.text"
	case dl == "opendocument text template":
		return "application/vnd.oasis.opendocument.text-template"
	case dl == "opendocument text web":
		return "application/vnd.oasis.opendocument.text-web"
	case dl == "opendocument text master":
		return "application/vnd.oasis.opendocument.text-master"
	case dl == "opendocument spreadsheet":
		return "application/vnd.oasis.opendocument.spreadsheet"
	case dl == "opendocument spreadsheet template":
		return "application/vnd.oasis.opendocument.spreadsheet-template"
	case dl == "opendocument presentation":
		return "application/vnd.oasis.opendocument.presentation"
	case dl == "opendocument presentation template":
		return "application/vnd.oasis.opendocument.presentation-template"
	case dl == "opendocument graphics":
		return "application/vnd.oasis.opendocument.graphics"
	case dl == "opendocument graphics template":
		return "application/vnd.oasis.opendocument.graphics-template"
	case dl == "opendocument chart":
		return "application/vnd.oasis.opendocument.chart"
	case dl == "opendocument chart template":
		return "application/vnd.oasis.opendocument.chart-template"
	case dl == "opendocument image":
		return "application/vnd.oasis.opendocument.image"
	case dl == "opendocument image template":
		return "application/vnd.oasis.opendocument.image-template"
	case dl == "opendocument formula":
		return "application/vnd.oasis.opendocument.formula"
	case dl == "opendocument formula template":
		return "application/vnd.oasis.opendocument.formula-template"
	case dl == "opendocument database":
		return "application/vnd.oasis.opendocument.database"
	case strings.HasPrefix(dl, "opendocument"):
		return "application/vnd.oasis.opendocument"
	case dl == "zip archive data":
		return "application/zip"

	// AR sub-types (doAr)
	case strings.Contains(dl, "debian binary package"):
		return "application/vnd.debian.binary-package"
	case dl == "ar archive":
		return "application/x-archive"

	// TAR sub-types (doTar)
	case strings.Contains(dl, "vmware ova appliance"):
		return "application/x-virtualbox-ova"
	case strings.Contains(dl, "posix tar archive"):
		return "application/x-tar"

	// 3GPP variants
	case strings.Contains(dl, "3gpp2 video file"):
		return "video/3gpp2"
	case strings.Contains(dl, "3gpp video file"):
		return "video/3gpp"

	// PGP variants
	case strings.Contains(dl, "pgp public key"), strings.Contains(dl, "pgp private key"),
		strings.Contains(dl, "pgp armored"), strings.Contains(dl, "pgp binary"):
		return "application/pgp-keys"
	case strings.Contains(dl, "pgp message"), strings.Contains(dl, "pgp signed message"):
		return "application/pgp-encrypted"
	case strings.Contains(dl, "pgp signature"):
		return "application/pgp-signature"

	// PEM variants — certificate request has a different MIME from all other PEM types
	case strings.Contains(dl, "pem certificate request"):
		return "application/pkcs10"
	case strings.Contains(dl, "pem "), strings.Contains(dl, "openssh private key"):
		return "application/x-pem-file"

	// Text sub-types — check specific sub-types before the generic text prefix
	case strings.Contains(dl, "apple mail message (emlx)"):
		return "message/rfc822"
	case strings.Contains(dl, "mbox mailbox"):
		return "application/mbox"
	case strings.Contains(dl, "markdown text"):
		return "text/markdown"
	case strings.Contains(dl, "openvpn config"):
		return "application/x-openvpn-profile"
	case strings.HasPrefix(dl, "ascii text"), strings.HasPrefix(dl, "utf-8 text"),
		strings.HasPrefix(dl, "non-utf text"), strings.HasPrefix(dl, "unicode text, utf-16"):
		return "text/plain"

	// XML sub-type: VMware VMXF is text/plain, plain XML falls through to octet-stream
	case strings.Contains(dl, "vmware supplemental configuration"):
		return "text/plain"
	}

	return "application/octet-stream"
}

func isText(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	if _, _, ok := decodeUTF16Text(b); ok {
		return true
	}

	// Some Windows batch files are saved in legacy 8-bit encodings (for example
	// cp1252 smart punctuation), so they fail strict UTF-8 validation despite
	// being clearly text.
	if looksLikeLegacyBatchText(b) {
		return true
	}
	// Legacy-encoded scripts with shebangs (for example perl/shell) may be
	// non-UTF but still should be classified as text.
	if looksLikeLegacyShebangText(b) {
		return true
	}
	// Some plain text files are encoded in legacy 8-bit encodings (ISO-8859/cp1252).
	if looksLikeLegacy8BitText(b) {
		return true
	}

	return isUTF8LikeText(b)
}

func looksLikeLegacyBatchText(b []byte) bool {
	if len(b) == 0 || utf8.Valid(b) {
		return false
	}
	if bytes.IndexByte(b, 0x00) >= 0 {
		return false
	}

	const maxScan = 32 * 1024
	end := len(b)
	if end > maxScan {
		end = maxScan
	}

	topLower := "\n" + strings.ToLower(string(b[:end]))
	return looksLikeBatch(topLower)
}

func looksLikeLegacyShebangText(b []byte) bool {
	if len(b) < 4 || utf8.Valid(b) {
		return false
	}
	if !bytes.HasPrefix(b, []byte("#!")) {
		return false
	}
	if bytes.IndexByte(b, 0x00) >= 0 {
		return false
	}

	end := len(b)
	if end > 4096 {
		end = 4096
	}
	headLower := strings.ToLower(string(b[:end]))
	if !(strings.Contains(headLower, "perl") || strings.Contains(headLower, "/sh") || strings.Contains(headLower, "bash")) {
		return false
	}

	badCtrl := 0
	for _, c := range b[:end] {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\f' && c != '\b' {
			badCtrl++
		}
	}
	return badCtrl == 0 || badCtrl*100/end <= 2
}

func looksLikeLegacy8BitText(b []byte) bool {
	if len(b) < 16 || utf8.Valid(b) {
		return false
	}
	if bytes.IndexByte(b, 0x00) >= 0 {
		return false
	}

	end := len(b)
	if end > 16*1024 {
		end = 16 * 1024
	}
	s := b[:end]

	badCtrl := 0
	printable := 0
	high := 0
	for _, c := range s {
		if c >= 0x80 {
			high++
			printable++
			continue
		}
		if c >= 0x20 || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == '\b' {
			printable++
			continue
		}
		badCtrl++
	}
	if high == 0 {
		return false
	}
	// Keep strict to avoid classifying binary blobs as text.
	if badCtrl*100/end > 1 {
		return false
	}
	return printable*100/end >= 90
}

func isUTF8LikeText(b []byte) bool {
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
	if label, decoded, ok := decodeUTF16Text(b); ok {
		base := "Unicode text, " + label + " text"
		subtype := detectTextSubtype(decoded)
		if subtype != "" {
			base += ", " + subtype
		}
		if endings := detectLineEndings(decoded); endings != "" {
			base += ", with " + endings + " line terminators"
		}
		return base
	}

	base := "UTF-8 text"
	if isASCIIOnly(b) {
		base = "ASCII text"
	} else if !utf8.Valid(b) {
		base = "Non-UTF text"
	}

	subtype := detectTextSubtype(b)
	if subtype != "" {
		base += ", " + subtype
	}
	if endings := detectLineEndings(b); endings != "" {
		base += ", with " + endings + " line terminators"
	}
	return base
}

func decodeUTF16Text(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}

	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		decoded, ok := decodeUTF16Bytes(b[2:], true)
		if ok {
			return "UTF-16, little-endian", decoded, true
		}
		return "", nil, false
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		decoded, ok := decodeUTF16Bytes(b[2:], false)
		if ok {
			return "UTF-16, big-endian", decoded, true
		}
		return "", nil, false
	}

	switch utf16EndiannessHeuristic(b) {
	case "le":
		decoded, ok := decodeUTF16Bytes(b, true)
		if ok {
			return "UTF-16, little-endian", decoded, true
		}
	case "be":
		decoded, ok := decodeUTF16Bytes(b, false)
		if ok {
			return "UTF-16, big-endian", decoded, true
		}
	}

	return "", nil, false
}

func decodeUTF16Bytes(b []byte, littleEndian bool) ([]byte, bool) {
	n := len(b)
	if n < 2 {
		return nil, false
	}
	if n%2 != 0 {
		n--
	}
	if n < 2 {
		return nil, false
	}

	u16s := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		var v uint16
		if littleEndian {
			v = uint16(b[i]) | uint16(b[i+1])<<8
		} else {
			v = uint16(b[i])<<8 | uint16(b[i+1])
		}
		u16s = append(u16s, v)
	}

	runes := utf16.Decode(u16s)
	if len(runes) == 0 {
		return nil, false
	}
	text := string(runes)
	if len(text) == 0 || !isUTF8LikeText([]byte(text)) {
		return nil, false
	}
	return []byte(text), true
}

func utf16EndiannessHeuristic(b []byte) string {
	end := len(b)
	if end > 4096 {
		end = 4096
	}
	if end%2 != 0 {
		end--
	}
	if end < 8 {
		return ""
	}

	pairs := end / 2
	oddZero := 0
	evenZero := 0
	lePrintable := 0
	bePrintable := 0

	for i := 0; i < end; i += 2 {
		lo := b[i]
		hi := b[i+1]
		if hi == 0 {
			oddZero++
			if isLikelyTextByte(lo) {
				lePrintable++
			}
		}
		if lo == 0 {
			evenZero++
			if isLikelyTextByte(hi) {
				bePrintable++
			}
		}
	}

	if oddZero*100/pairs >= 55 && lePrintable*100/pairs >= 50 {
		return "le"
	}
	if evenZero*100/pairs >= 55 && bePrintable*100/pairs >= 50 {
		return "be"
	}
	return ""
}

func isLikelyTextByte(c byte) bool {
	return c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7E)
}

func detectLineEndings(b []byte) string {
	hasCRLF := bytes.Contains(b, []byte("\r\n"))
	withoutCRLF := bytes.ReplaceAll(b, []byte("\r\n"), []byte{})
	hasLF := bytes.Contains(withoutCRLF, []byte("\n"))
	hasCR := bytes.Contains(withoutCRLF, []byte("\r"))

	switch {
	case hasCRLF && !hasLF && !hasCR:
		return "CRLF"
	case !hasCRLF && hasLF && !hasCR:
		return "LF"
	case !hasCRLF && !hasLF && hasCR:
		return "CR"
	case hasCRLF || hasLF || hasCR:
		return "mixed"
	default:
		return ""
	}
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
		hasContentTypes := false
		hasRels := false
		hasXMLPayload := false
		hasAPKManifest := false
		hasDexPayload := false
		hasAABManifest := false
		hasAABBundleConfig := false
		hasKMZDoc := false
		hasIPSWBuildManifest := false
		hasIPSWRestorePlist := false
		hasJarManifest := false
		hasWarWebInf := false
		hasEarAppXML := false
		hasNuspec := false
		hasNugetMeta := false
		hasVsixManifest := false

		// Loop through the files in the ZIP archive
		for _, zipFile := range zipReader.File {
			lowerName := strings.ToLower(zipFile.Name)
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
				mimeSample := strings.TrimSpace(string(first200Bytes))
				if desc := openDocumentDescriptionForMIME(mimeSample); desc != "" {
					return desc
				}
				if strings.Contains(mimeSample, "epub") {
					return "EPUB document"
				}
			}

			if lowerName == "appmanifest.xaml" || lowerName == "wmappmanifest.xml" {
				return "Microsoft Silverlight Application"
			}
			if lowerName == "designmap.xml" {
				return "Adobe InDesign IDML package"
			}
			if lowerName == "androidmanifest.xml" {
				hasAPKManifest = true
			}
			if lowerName == "classes.dex" || (strings.HasPrefix(lowerName, "classes") && strings.HasSuffix(lowerName, ".dex")) {
				hasDexPayload = true
			}
			if lowerName == "base/manifest/androidmanifest.xml" {
				hasAABManifest = true
			}
			if lowerName == "bundleconfig.pb" {
				hasAABBundleConfig = true
			}
			if lowerName == "doc.kml" {
				hasKMZDoc = true
			}
			if lowerName == "buildmanifest.plist" {
				hasIPSWBuildManifest = true
			}
			if lowerName == "restore.plist" {
				hasIPSWRestorePlist = true
			}
			if lowerName == "meta-inf/manifest.mf" {
				hasJarManifest = true
			}
			if strings.HasPrefix(lowerName, "web-inf/") {
				hasWarWebInf = true
			}
			if lowerName == "meta-inf/application.xml" {
				hasEarAppXML = true
			}
			if strings.HasSuffix(lowerName, ".nuspec") {
				hasNuspec = true
			}
			if strings.HasPrefix(lowerName, "package/services/metadata/core-properties/") && strings.HasSuffix(lowerName, ".psmdcp") {
				hasNugetMeta = true
			}
			if lowerName == "extension.vsixmanifest" || lowerName == "vsixmanifest" {
				hasVsixManifest = true
			}
			if lowerName == "[content_types].xml" {
				hasContentTypes = true
			}
			if strings.HasPrefix(lowerName, "_rels/") {
				hasRels = true
			}
			if strings.HasSuffix(lowerName, ".xml") {
				hasXMLPayload = true
			}
		}

		if hasAPKManifest && hasDexPayload {
			return "Android application package (APK)"
		}
		if hasAABManifest && (hasAABBundleConfig || hasDexPayload) {
			return "Android app bundle (AAB)"
		}
		if hasKMZDoc {
			return "KMZ geospatial archive"
		}
		if hasIPSWBuildManifest && hasIPSWRestorePlist {
			return "Apple IPSW firmware package"
		}
		if hasVsixManifest {
			return "Visual Studio extension package (VSIX)"
		}
		if hasNuspec || (hasNugetMeta && hasContentTypes) {
			return "NuGet package (NUPKG)"
		}
		if hasWarWebInf {
			return "Java WAR archive"
		}
		if hasEarAppXML {
			return "Java EAR archive"
		}
		if hasJarManifest {
			return "Java JAR archive"
		}
		if hasContentTypes && hasRels && hasXMLPayload {
			return "Microsoft OOXML"
		}
	}

	return "Zip archive data"
}

func openDocumentDescriptionForMIME(mime string) string {
	switch mime {
	case "application/vnd.oasis.opendocument.text":
		return "OpenDocument text"
	case "application/vnd.oasis.opendocument.text-template":
		return "OpenDocument text template"
	case "application/vnd.oasis.opendocument.text-web":
		return "OpenDocument text web"
	case "application/vnd.oasis.opendocument.text-master":
		return "OpenDocument text master"
	case "application/vnd.oasis.opendocument.spreadsheet":
		return "OpenDocument spreadsheet"
	case "application/vnd.oasis.opendocument.spreadsheet-template":
		return "OpenDocument spreadsheet template"
	case "application/vnd.oasis.opendocument.presentation":
		return "OpenDocument presentation"
	case "application/vnd.oasis.opendocument.presentation-template":
		return "OpenDocument presentation template"
	case "application/vnd.oasis.opendocument.graphics":
		return "OpenDocument graphics"
	case "application/vnd.oasis.opendocument.graphics-template":
		return "OpenDocument graphics template"
	case "application/vnd.oasis.opendocument.chart":
		return "OpenDocument chart"
	case "application/vnd.oasis.opendocument.chart-template":
		return "OpenDocument chart template"
	case "application/vnd.oasis.opendocument.image":
		return "OpenDocument image"
	case "application/vnd.oasis.opendocument.image-template":
		return "OpenDocument image template"
	case "application/vnd.oasis.opendocument.formula":
		return "OpenDocument formula"
	case "application/vnd.oasis.opendocument.formula-template":
		return "OpenDocument formula template"
	case "application/vnd.oasis.opendocument.database":
		return "OpenDocument database"
	case "application/vnd.oasis.opendocument":
		return "OpenDocument"
	default:
		if strings.HasPrefix(mime, "application/vnd.oasis.opendocument.") {
			return "OpenDocument"
		}
		return ""
	}
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

func doAr(file *os.File) string {
	if file == nil {
		return "ar archive"
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "ar archive"
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil || !bytes.Equal(header, []byte("!<arch>\n")) {
		return "ar archive"
	}

	const maxEntries = 200

	hasDebianBinary := false
	format := ""
	controlTar := ""
	dataComp := ""

	for i := 0; i < maxEntries; i++ {
		hdr := make([]byte, 60)
		_, err := io.ReadFull(file, hdr)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "ar archive"
		}
		if hdr[58] != '`' || hdr[59] != '\n' {
			return "ar archive"
		}

		name := normalizeArEntryName(string(hdr[:16]))
		lower := strings.ToLower(name)

		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		size, err := strconv.Atoi(sizeStr)
		if err != nil || size < 0 {
			return "ar archive"
		}

		readAndDiscard := func(n int) error {
			if n <= 0 {
				return nil
			}
			_, err := io.CopyN(io.Discard, file, int64(n))
			return err
		}

		readN := 0
		switch {
		case lower == "debian-binary":
			hasDebianBinary = true
			readN = size
			if readN > 64 {
				readN = 64
			}
			buf := make([]byte, readN)
			if _, err := io.ReadFull(file, buf); err != nil {
				return "ar archive"
			}
			format = strings.TrimSpace(string(buf))
		case strings.HasPrefix(lower, "control.tar."):
			controlTar = name
		case strings.HasPrefix(lower, "data.tar."):
			dataComp = tarPayloadCompression(lower)
		}

		if err := readAndDiscard(size - readN); err != nil {
			return "ar archive"
		}
		if size%2 != 0 {
			if _, err := file.Seek(1, io.SeekCurrent); err != nil {
				return "ar archive"
			}
		}
	}

	if hasDebianBinary && controlTar != "" {
		if format == "" {
			format = "2.0"
		}
		desc := "Debian binary package (format " + format + "), with " + controlTar
		if dataComp != "" {
			desc += ", data compression " + dataComp
		}
		return desc
	}
	return "ar archive"
}

func normalizeArEntryName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "/")
	return name
}

func tarPayloadCompression(name string) string {
	switch {
	case strings.HasSuffix(name, ".zst"):
		return "zst"
	case strings.HasSuffix(name, ".zs"):
		return "zs"
	case strings.HasSuffix(name, ".xz"):
		return "xz"
	case strings.HasSuffix(name, ".gz"):
		return "gzip"
	case strings.HasSuffix(name, ".bz2"):
		return "bzip2"
	default:
		return ""
	}
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
