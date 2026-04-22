PROJECT  = GhostBuster
SCHEME   = $(PROJECT)
BUILD_DIR = $(CURDIR)/.build
INSTALL_DIR = /usr/local/bin

.PHONY: debug install

debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(SCHEME) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

install: debug
	sudo cp $(BUILD_DIR)/Debug/$(PROJECT) $(INSTALL_DIR)/ghostbuster
	sudo chown root $(INSTALL_DIR)/ghostbuster
	sudo chmod u+s $(INSTALL_DIR)/ghostbuster
	sudo codesign --force --sign - --entitlements Sources/GhostBuster/GhostBuster.entitlements --timestamp=none $(INSTALL_DIR)/ghostbuster
	@echo "Installed to $(INSTALL_DIR)/ghostbuster (setuid root, re-signed)"
