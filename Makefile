APP_NAME := spear
PLUGIN_DIRS := $(wildcard plugins/*)

.PHONY: all build plugins clean shrink

all: build plugins

## Build main app
build:
	@echo ">> Building $(APP_NAME)..."
	go build -o build/$(APP_NAME) ./cmd/$(APP_NAME)/main.go

## Build all plugins
plugins:
	@echo ">> Building plugins..."
	@for dir in $(PLUGIN_DIRS); do \
		$(MAKE) -C $$dir; \
	done

## Clean everything
clean:
	@echo ">> Cleaning..."
	@rm -rf build/
	@for dir in $(PLUGIN_DIRS); do \
		$(MAKE) -C $$dir clean || true; \
	done

## Shrink binaries with UPX
shrink:
	@if ! command -v upx >/dev/null 2>&1; then \
		echo "❌ upx isn't installed."; \
		exit 1; \
	fi
	@echo "📦 Compressing binrary..."
	@if [ -f build/$(APP_NAME) ]; then \
		upx --best --lzma build/$(APP_NAME); \
	fi
	@echo "📦 Compressing plugins..."
	strip --strip-unneeded build/plugins/*.so
	@echo "✅ Compression finished."
