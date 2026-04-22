PROJECT  = Tractor
SCHEME   = $(PROJECT)
BUILD_DIR = $(CURDIR)/.build

.PHONY: debug clean

debug:
	xcodegen generate
	xcodebuild -project $(PROJECT).xcodeproj -scheme $(SCHEME) -configuration Debug \
		SYMROOT=$(BUILD_DIR) OBJROOT=$(BUILD_DIR) build

clean:
	rm -rf $(BUILD_DIR)
