[@joeky888](https://github.com/joeky888) needs `file` command on Windows, so he made one.

![Screen shot](https://i.imgur.com/SiV176F.png)

### Features

* Pure Go, static binary without [libmagic](http://darwinsys.com/file)
* Lightweight, The only dependency is [os](https://golang.org/pkg/os)
* Cross-platform: No unix specific code like [mmap](https://godoc.org/golang.org/x/exp/mmap)

### Install

```sh
go get -u github.com/joeky888/fil
```

### Usage

Just like unix [file](https://en.wikipedia.org/wiki/File_(command)) command

```sh
$ fil <FILE_NAME>
```

### MIT Licence

The code is based on [toybox](https://en.wikipedia.org/wiki/Toybox) (but it is written in C, and only runs on unix-like OS)

### TODO

1. Port more code from [toybox/file.c](https://github.com/landley/toybox/blob/master/toys/posix/file.c)
2. Port more code from [filetype/matchers](https://github.com/h2non/filetype/tree/master/matchers)
