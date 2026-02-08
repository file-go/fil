package main

import "os"

var matcherText = fileMatcher{
	name:   "text",
	minLen: 1,
	match: func(b []byte, lenb int, magic int) bool {
		return isText(b)
	},
	describe: func(b []byte, lenb int, magic int, file *os.File) string {
		return describeText(b)
	},
}
