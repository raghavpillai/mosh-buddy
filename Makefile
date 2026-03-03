BINARY := mb
VERSION := 0.1.0
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
GO := $(shell which go 2>/dev/null || echo $(HOME)/go-sdk/go/bin/go)

INSTALL_DIR := $(HOME)/.local/bin

.PHONY: build install all clean test

build:
	$(GO) build -ldflags="-s -w" -o $(BINARY) ./cmd/mb

install: build
	@mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@if [ "$$(uname)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(BINARY); \
		xattr -cr $(INSTALL_DIR)/$(BINARY); \
	fi

test:
	$(GO) test ./...

all:
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch $(GO) build -ldflags="-s -w" \
			-o build/$(BINARY)-$$os-$$arch ./cmd/mb; \
	done

clean:
	rm -rf build/ $(BINARY)
