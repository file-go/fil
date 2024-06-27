![Screen shot](https://i.imgur.com/Ike5iIJ.png)

### Features

* Pure Go, static binary without [libmagic](http://darwinsys.com/file)
* Cross-platform: No unix specific code like [mmap](https://godoc.org/golang.org/x/exp/mmap)

### Install binary

Download from https://github.com/file-go/fil/releases

### Install from source

```sh
go install github.com/file-go/fil@latest
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
3. [More magic](https://en.wikipedia.org/wiki/Magic_number_(programming))
