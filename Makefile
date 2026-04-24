PROJECT   = Tractor
BUILD_DIR = $(CURDIR)/.build
INSTALL_APP  = /Applications/Tractor.app
SYMLINK      = /usr/local/bin/tractor
PKG_DIR      = $(BUILD_DIR)/pkg
PKG_OUT      = $(BUILD_DIR)/Tractor.pkg

.PHONY: debug release pkg install uninstall clean

# Debug: bare tool binary, works with SIP disabled (development/testing)
debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(PROJECT) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

# Release: .app bundle suitable for signing, notarization, and provisioning profiles
release:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme TractorApp -configuration Release \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

# Pkg: build a .pkg installer
pkg: release
	rm -rf "$(PKG_DIR)"
	mkdir -p "$(PKG_DIR)/payload/Library/Application Support/Tractor"
	cp -R "$(BUILD_DIR)/Release/Tractor.app" "$(PKG_DIR)/payload/Library/Application Support/Tractor/"
	pkgbuild --root "$(PKG_DIR)/payload" \
		--scripts pkg/scripts \
		--identifier com.jacobgroundwater.Tractor \
		--version 0.1.0 \
		--install-location / \
		"$(PKG_DIR)/Tractor-component.pkg"
	productbuild --distribution pkg/distribution.xml \
		--package-path "$(PKG_DIR)" \
		"$(PKG_OUT)"
	@echo ""
	@echo "Package: $(PKG_OUT)"

# Install: build .app bundle and install to /Applications
install: release
	sudo rm -rf "$(INSTALL_APP)"
	sudo cp -R "$(BUILD_DIR)/Release/Tractor.app" "$(INSTALL_APP)"
	sudo mkdir -p $(dir $(SYMLINK))
	sudo ln -sf "$(INSTALL_APP)/Contents/MacOS/Tractor" "$(SYMLINK)"
	@echo ""
	@echo "Installed: $(INSTALL_APP)"
	@echo "Symlink:   $(SYMLINK) -> $(INSTALL_APP)/Contents/MacOS/Tractor"

uninstall:
	sudo rm -f "$(SYMLINK)"
	sudo rm -rf "$(INSTALL_APP)"
	@echo "Uninstalled."

clean:
	rm -rf $(BUILD_DIR)
