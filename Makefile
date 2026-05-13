PROJECT      = Tractor
BUILD_DIR    = $(CURDIR)/.build
DIST_DIR     = $(BUILD_DIR)/dist
PKG_DIR      = $(BUILD_DIR)/pkg
DMG_DIR      = $(BUILD_DIR)/dmg

VERSION       := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
DEV_TEAM      := $(shell awk -F= '/^DEVELOPMENT_TEAM[[:space:]]*=/{gsub(/[[:space:]]/,"",$$2); print $$2}' Local.xcconfig 2>/dev/null)
DEV_ID_APP    := $(shell security find-identity -v -p codesigning 2>/dev/null | grep "Developer ID Application" | grep "($(DEV_TEAM))" | head -1 | sed -E 's/.*"(.*)".*/\1/')
ARCHIVE_PATH   = $(BUILD_DIR)/Tractor.xcarchive
EXPORT_DIR     = $(BUILD_DIR)/Release
APP_BUILT      = $(EXPORT_DIR)/Tractor.app
PKG_OUT        = $(DIST_DIR)/Tractor-$(VERSION).pkg
DMG_OUT        = $(DIST_DIR)/Tractor-$(VERSION).dmg

# Makefile-only release config (signing identity, notarytool profile).
# See Local.mk.example. Optional for `make debug` / `make release`.
-include Local.mk

.PHONY: debug release pkg pkg-from-release notarize dmg dmg-from-release \
        notarize-dmg dist dist-homebrew clean preflight-release preflight-pkg \
        preflight-dmg preflight-notarize bump-sysext-version ensure-local-config

# Auto-create Local.xcconfig from the example if it's missing so xcodegen
# doesn't fail for contributors who only want to run `make debug`.
ensure-local-config:
	@test -f Local.xcconfig || { \
		echo "Local.xcconfig missing — seeding from Local.xcconfig.example"; \
		cp Local.xcconfig.example Local.xcconfig; \
	}

# Debug: build the .app bundle (with both sysexts embedded) ad-hoc signed.
# Useful for local iteration with SIP disabled. Output at .build/Debug/Tractor.app.
debug: ensure-local-config
	xcodegen generate
	@for t in TractorNE TractorES; do \
		sed -i '' "/$$t/,/productType/{s/productType = \"com.apple.product-type.bundle\";/productType = \"com.apple.product-type.system-extension\";/;}" $(PROJECT).xcodeproj/project.pbxproj; \
	done
	xcodebuild -project $(PROJECT).xcodeproj -scheme TractorApp -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) \
		ENABLE_DEBUG_DYLIB=NO ENABLE_PREVIEWS=NO \
		CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY="-" build

# Auto-increment sysext build number so macOS recognizes replacement
bump-sysext-version:
	@OLD=$$(awk '/CFBundleVersion:/{gsub(/"/,""); print $$2; exit}' project.yml); \
	NEW=$$((OLD + 1)); \
	awk -v n="$$NEW" '/CFBundleVersion:/ && !done {sub(/"[0-9]+"/, "\"" n "\""); done=1} 1' project.yml > project.yml.tmp && \
	mv project.yml.tmp project.yml; \
	echo "Tractor: sysext build number → $$NEW"

preflight-release: ensure-local-config
	@grep -E '^DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*[A-Z0-9]{10}' Local.xcconfig > /dev/null \
		|| { echo "ERROR: DEVELOPMENT_TEAM is not set in Local.xcconfig."; exit 1; }
	@security find-identity -v -p codesigning | grep -q "Developer ID Application" \
		|| { echo "ERROR: no 'Developer ID Application' identity in keychain."; exit 1; }

# Release: signed .app bundle (Developer ID + hardened runtime + secure timestamp).
# Archive runs with normal signing against the auto-managed Apple Development
# profile (entitlements files use the plain `app-proxy-provider` value that
# the dev profile authorises). exportArchive then auto-creates / refreshes the
# Developer ID Direct profiles and re-signs. We re-sign once more after that
# to substitute the distribution-time entitlements (-systemextension variant
# for NE) and apply hardened runtime + secure timestamp.
release: preflight-release bump-sysext-version
	xcodegen generate
	@# XcodeGen creates bundles for both sysexts, but they need system-extension product type.
	@for t in TractorNE TractorES; do \
		sed -i '' "/$$t/,/productType/{s/productType = \"com.apple.product-type.bundle\";/productType = \"com.apple.product-type.system-extension\";/;}" $(PROJECT).xcodeproj/project.pbxproj; \
	done
	rm -rf "$(ARCHIVE_PATH)" "$(EXPORT_DIR)"
	xcodebuild -project $(PROJECT).xcodeproj -scheme TractorApp -configuration Release \
		-archivePath "$(ARCHIVE_PATH)" \
		MARKETING_VERSION=$(VERSION) \
		CODE_SIGN_IDENTITY="Apple Development" \
		DEVELOPMENT_TEAM=$(DEV_TEAM) \
		-allowProvisioningUpdates \
		archive
	@# exportArchive does two things for us: it auto-creates / refreshes the
	@# Developer ID ("Direct") provisioning profiles for any bundle in the
	@# archive that doesn't already have one, and it re-signs with Developer
	@# ID. We don't actually use the export output (the codesign re-sign step
	@# below substitutes -systemextension entitlements for NE), but running
	@# exportArchive is how we get the profile cache populated.
	xcodebuild -exportArchive \
		-archivePath "$(ARCHIVE_PATH)" \
		-exportPath "$(EXPORT_DIR).pre" \
		-exportOptionsPlist pkg/ExportOptions.plist \
		-allowProvisioningUpdates || true
	mkdir -p "$(EXPORT_DIR)"
	ditto "$(ARCHIVE_PATH)/Products/Applications/Tractor.app" "$(APP_BUILT)"
	@# Embed the Xcode-managed Developer ID profiles for the app and both sysexts.
	@# exportArchive normally embeds them, but archive ran with CODE_SIGNING_ALLOWED=NO,
	@# so the profile wiring is skipped. AMFI rejects restricted entitlements without them.
	@PROFILES_DIR="$$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; \
	APP_PROFILE=""; NE_PROFILE=""; ES_PROFILE=""; \
	for p in "$$PROFILES_DIR"/*.provisionprofile; do \
		name=$$(security cms -D -i "$$p" 2>/dev/null | plutil -extract Name raw -o - -); \
		case "$$name" in \
			"Mac Team Direct Provisioning Profile: com.jacobgroundwater.Tractor") APP_PROFILE="$$p" ;; \
			"Mac Team Direct Provisioning Profile: com.jacobgroundwater.Tractor.NE") NE_PROFILE="$$p" ;; \
			"Mac Team Direct Provisioning Profile: com.jacobgroundwater.Tractor.ES") ES_PROFILE="$$p" ;; \
		esac; \
	done; \
	test -n "$$APP_PROFILE" && test -n "$$NE_PROFILE" && test -n "$$ES_PROFILE" \
		|| { echo "ERROR: missing Developer ID profile for Tractor / .NE / .ES in $$PROFILES_DIR"; exit 1; }; \
	cp "$$APP_PROFILE" "$(APP_BUILT)/Contents/embedded.provisionprofile"; \
	cp "$$NE_PROFILE" "$(APP_BUILT)/Contents/Library/SystemExtensions/com.jacobgroundwater.Tractor.NE.systemextension/Contents/embedded.provisionprofile"; \
	cp "$$ES_PROFILE" "$(APP_BUILT)/Contents/Library/SystemExtensions/com.jacobgroundwater.Tractor.ES.systemextension/Contents/embedded.provisionprofile"
	@# exportArchive doesn't re-apply hardened runtime when archive ran with
	@# CODE_SIGNING_ALLOWED=NO, so re-sign each binary with --options runtime + timestamp.
	@# Sysexts first (inside-out), then the outer app so its seal covers them.
	codesign --force \
		--sign "$(DEV_ID_APP)" \
		--entitlements pkg/TractorNE.dist.entitlements \
		--options runtime --timestamp \
		"$(APP_BUILT)/Contents/Library/SystemExtensions/com.jacobgroundwater.Tractor.NE.systemextension"
	codesign --force \
		--sign "$(DEV_ID_APP)" \
		--entitlements Sources/TractorES/TractorES.entitlements \
		--options runtime --timestamp \
		"$(APP_BUILT)/Contents/Library/SystemExtensions/com.jacobgroundwater.Tractor.ES.systemextension"
	codesign --force \
		--sign "$(DEV_ID_APP)" \
		--entitlements pkg/TractorApp.dist.entitlements \
		--options runtime --timestamp \
		"$(APP_BUILT)"
	@echo ""
	@echo "Release app: $(APP_BUILT)"
	@codesign -dv --verbose=2 "$(APP_BUILT)" 2>&1 | grep -E "Authority|TeamIdentifier|Runtime|flags" || true

preflight-pkg:
	@test -n "$(INSTALLER_SIGN_IDENTITY)" \
		|| { echo "ERROR: INSTALLER_SIGN_IDENTITY is not set (see Local.mk.example)."; exit 1; }
	@security find-identity -v -p basic | grep -q "Developer ID Installer" \
		|| { echo "ERROR: no 'Developer ID Installer' identity in keychain."; exit 1; }

# Pkg: signed .pkg installer wrapping the Release .app
pkg: release pkg-from-release

pkg-from-release: preflight-pkg
	@test -d "$(APP_BUILT)" \
		|| { echo "ERROR: $(APP_BUILT) not found — run 'make release' first."; exit 1; }
	rm -rf "$(PKG_DIR)"
	mkdir -p "$(PKG_DIR)/payload/Library/Application Support/Tractor"
	mkdir -p "$(DIST_DIR)"
	cp -R "$(APP_BUILT)" "$(PKG_DIR)/payload/Library/Application Support/Tractor/"
	sed -e 's/@VERSION@/$(VERSION)/g' pkg/distribution.xml.in > "$(PKG_DIR)/distribution.xml"
	pkgbuild --root "$(PKG_DIR)/payload" \
		--scripts pkg/scripts \
		--identifier com.jacobgroundwater.Tractor \
		--version $(VERSION) \
		--install-location / \
		"$(PKG_DIR)/Tractor-component.pkg"
	productbuild --distribution "$(PKG_DIR)/distribution.xml" \
		--package-path "$(PKG_DIR)" \
		--sign "$(INSTALLER_SIGN_IDENTITY)" \
		--timestamp \
		"$(PKG_OUT)"
	@echo ""
	@echo "Signed pkg: $(PKG_OUT)"
	@pkgutil --check-signature "$(PKG_OUT)" | head -8

preflight-dmg:
	@test -d "$(APP_BUILT)" \
		|| { echo "ERROR: $(APP_BUILT) not found — run 'make release' first."; exit 1; }

# Dmg: Homebrew-friendly disk image containing the Release .app
dmg: release dmg-from-release

dmg-from-release: preflight-dmg
	rm -rf "$(DMG_DIR)"
	mkdir -p "$(DMG_DIR)"
	mkdir -p "$(DIST_DIR)"
	cp -R "$(APP_BUILT)" "$(DMG_DIR)/Tractor.app"
	hdiutil create -volname "Tractor" \
		-srcfolder "$(DMG_DIR)" \
		-ov -format UDZO \
		"$(DMG_OUT)"
	@echo ""
	@echo "Unsigned dmg: $(DMG_OUT)"

preflight-notarize:
	@test -n "$(NOTARYTOOL_KEYCHAIN_PROFILE)" \
		|| { echo "ERROR: NOTARYTOOL_KEYCHAIN_PROFILE is not set (see Local.mk.example)."; exit 1; }
	@test -f "$(PKG_OUT)" \
		|| { echo "ERROR: $(PKG_OUT) not found — run 'make pkg' first."; exit 1; }

# Notarize: submit the signed pkg, wait, then staple
notarize: preflight-notarize
	xcrun notarytool submit "$(PKG_OUT)" \
		--keychain-profile "$(NOTARYTOOL_KEYCHAIN_PROFILE)" \
		--wait
	xcrun stapler staple "$(PKG_OUT)"
	xcrun stapler validate "$(PKG_OUT)"
	@echo ""
	@echo "Notarized + stapled: $(PKG_OUT)"

notarize-dmg:
	@test -n "$(NOTARYTOOL_KEYCHAIN_PROFILE)" \
		|| { echo "ERROR: NOTARYTOOL_KEYCHAIN_PROFILE is not set (see Local.mk.example)."; exit 1; }
	@test -f "$(DMG_OUT)" \
		|| { echo "ERROR: $(DMG_OUT) not found — run 'make dmg' first."; exit 1; }
	xcrun notarytool submit "$(DMG_OUT)" \
		--keychain-profile "$(NOTARYTOOL_KEYCHAIN_PROFILE)" \
		--wait
	xcrun stapler staple "$(DMG_OUT)"
	xcrun stapler validate "$(DMG_OUT)"
	@echo ""
	@echo "Notarized + stapled: $(DMG_OUT)"

# Dist: produce final release artifacts (signed, notarized, stapled, checksummed)
dist: pkg notarize
	cd "$(DIST_DIR)" && shasum -a 256 "Tractor-$(VERSION).pkg" > "Tractor-$(VERSION).pkg.sha256"
	@echo ""
	@echo "Release artifacts in $(DIST_DIR):"
	@ls -lh "$(DIST_DIR)"
	@echo ""
	@echo "Upload manually, e.g.:"
	@echo "  gh release create v$(VERSION) --generate-notes \\"
	@echo "    \"$(PKG_OUT)\" \\"
	@echo "    \"$(PKG_OUT).sha256\""

dist-homebrew: dmg notarize-dmg
	cd "$(DIST_DIR)" && shasum -a 256 "Tractor-$(VERSION).dmg" > "Tractor-$(VERSION).dmg.sha256"
	@echo ""
	@echo "Homebrew release artifacts in $(DIST_DIR):"
	@ls -lh "$(DIST_DIR)"
	@echo ""
	@echo "Upload manually, e.g.:"
	@echo "  gh release create v$(VERSION) --generate-notes \\"
	@echo "    \"$(DMG_OUT)\" \\"
	@echo "    \"$(DMG_OUT).sha256\""

clean:
	rm -rf $(BUILD_DIR)
