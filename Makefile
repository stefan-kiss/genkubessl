VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")

# Use linker flags to provide version/build settings
LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GO111MODULE=on

#export GOPATH
export GO111MODULE

all: clean get test build-darwin build-linux build-windows

build: test build-darwin build-linux build-windows

clean:
	$(GOCLEAN) ./...
	rm -rf bin/*

get:
	$(GOGET) ./...

test:
		$(GOTEST) ./...

build-linux:
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -v -o "bin/gencrt-$(VERSION)-linux-amd64" cmd/gencrt/main.go
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -v -o "bin/genkubessl-$(VERSION)-linux-amd64" cmd/genkubessl/main.go
build-windows:
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -v -o "bin/gencrt-$(VERSION)-windows-amd64.exe" cmd/gencrt/main.go
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -v -o "bin/genkubessl-$(VERSION)-windows-amd64.exe" cmd/genkubessl/main.go
build-darwin:
		CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -v -o "bin/gencrt-$(VERSION)-darwin-amd64" cmd/gencrt/main.go
		CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -v -o "bin/genkubessl-$(VERSION)-darwin-amd64" cmd/genkubessl/main.go