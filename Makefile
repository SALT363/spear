APP_NAME := spear
PLUGIN_DIRS := $(wildcard plugins/*)

.PHONY: all build plugins clean

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
