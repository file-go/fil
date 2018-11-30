#!/bin/sh

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fil-linux-x64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o fil-linux-arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm   go build -o fil-linux-arm

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o fil-win-x64.exe

CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o fil-osx-x64
