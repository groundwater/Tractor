PROJECT  = GhostBuster
SCHEME   = $(PROJECT)
BUILD_DIR = $(CURDIR)/.build

.PHONY: debug setuid

debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(SCHEME) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

setuid: debug
	sudo chown root $(BUILD_DIR)/Debug/$(PROJECT)
	sudo chmod u+s $(BUILD_DIR)/Debug/$(PROJECT)
	sudo codesign --force --sign - --entitlements Sources/GhostBuster/GhostBuster.entitlements --timestamp=none $(BUILD_DIR)/Debug/$(PROJECT)
	@echo "$(BUILD_DIR)/Debug/$(PROJECT) is now setuid root"
