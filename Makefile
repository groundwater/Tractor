PROJECT  = GhostBuster
SCHEME   = $(PROJECT)
BUILD_DIR = $(CURDIR)/.build

.PHONY: debug

debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(SCHEME) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build
