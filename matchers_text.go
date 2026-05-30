package main

import "os"

var matcherText = fileMatcher{
	name:   "text",
	minLen: 1,
	mime:   "", // dynamic: varies by sub-type (text/plain, text/markdown, application/mbox, etc.)
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return isText(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeText(b)
	},
}

var matcherDataFallback = fileMatcher{
	name:   "data",
	minLen: 1,
	mime:   "application/octet-stream",
	match: func(b []byte, lenb int, magic int, _ *os.File) bool {
		return !isText(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return "data"
	},
}
