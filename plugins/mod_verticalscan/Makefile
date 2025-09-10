PLUGIN_NAME = mod_verticalscan
OUTPUT_DIR = ../../build/plugins
PLUGIN_FILE = $(OUTPUT_DIR)/$(PLUGIN_NAME).so

# Go compiler settings
GO = go
GOFLAGS = -buildmode=plugin
LDFLAGS = -w -s

# Source files
SOURCES = verticalscan.go

.PHONY: all build clean install deps

all: deps build

deps:
	@echo "Installing dependencies..."
	$(GO) mod tidy

build: $(PLUGIN_FILE)

$(PLUGIN_FILE): $(SOURCES) | $(OUTPUT_DIR)
	@echo "Building $(PLUGIN_NAME) plugin..."
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(PLUGIN_FILE) $(SOURCES)
	@echo "Plugin built successfully: $(PLUGIN_FILE)"

$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

clean:
	@echo "Cleaning $(PLUGIN_NAME) plugin..."
	@rm -f $(PLUGIN_FILE)
	@echo "Clean completed"

install: build
	@echo "Installing $(PLUGIN_NAME) plugin..."
	@sudo mkdir -p /usr/lib/spear/plugins
	@sudo cp $(PLUGIN_FILE) /usr/lib/spear/plugins/
	@echo "Plugin installed to /usr/lib/spear/plugins/$(PLUGIN_NAME).so"
	@echo "Note: This plugin requires root privileges to capture packets"

uninstall:
	@echo "Uninstalling $(PLUGIN_NAME) plugin..."
	@sudo rm -f /usr/lib/spear/plugins/$(PLUGIN_NAME).so
	@echo "Plugin uninstalled"

test:
	@echo "Testing $(PLUGIN_NAME) plugin..."
	$(GO) vet $(SOURCES)
	$(GO) fmt $(SOURCES)
	@echo "Tests completed"

dev: clean deps build
	@echo "Development build completed"

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  deps      - Install dependencies"
	@echo "  build     - Build the plugin"
	@echo "  clean     - Remove built files"
	@echo "  install   - Install plugin to system directory (requires sudo)"
	@echo "  uninstall - Remove plugin from system directory (requires sudo)"
	@echo "  test      - Run code validation"
	@echo "  dev       - Clean, install deps and build for development"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Note: This plugin requires root privileges to capture network packets"
	@echo "      Make sure to run Spear as root when using this plugin"