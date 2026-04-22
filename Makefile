PROJECT  = GhostBuster
SCHEME   = $(PROJECT)
BUILD_DIR = $(CURDIR)/.build
BIN      = $(CURDIR)/ghostbuster

.PHONY: debug install clean

debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(SCHEME) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

install: debug
	cp $(BUILD_DIR)/Debug/$(PROJECT) $(BIN)
	sudo chown root $(BIN)
	sudo chmod u+s $(BIN)
	sudo codesign --force --sign - --entitlements Sources/GhostBuster/GhostBuster.entitlements --timestamp=none $(BIN)
	@echo "$(BIN) ready (setuid root)"

clean:
	rm -rf $(BUILD_DIR) $(BIN)
