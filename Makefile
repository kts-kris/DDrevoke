CXX       := clang++
ARCH      := arm64
CXXFLAGS  := -arch $(ARCH) -std=c++17 -O2 -Wall -Wextra -fPIC -fobjc-arc
LDFLAGS   := -dynamiclib -framework Foundation -framework AppKit -Wl,-install_name,@rpath/libDDRevoke.dylib

BUILD_DIR := build
TARGET    := $(BUILD_DIR)/libDDRevoke.dylib
SRC       := src/DDRevoke.mm

.PHONY: all clean verify

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<
	@codesign --force --sign - $@
	@echo "[+] Built and ad-hoc signed: $@"

verify: $(TARGET)
	@echo "=== 1. Checking $(TARGET) Mach-O & Architecture ==="
	@file $(TARGET)
	@otool -L $(TARGET)
	@echo "=== 2. Verifying Target DingTalk 9.0.1 Binary Prolog Signatures ==="
	@python3 scripts/verify_target.py

clean:
	rm -rf $(BUILD_DIR)
