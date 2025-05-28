# Compiler and flags
CLANG ?= clang
LLC ?= llc
RM ?= rm -rf

# Adjust CFLAGS and LDFLAGS as needed for your environment and libbpf location
# Common flags for eBPF compilation
CFLAGS := -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu \
          -O2 -g -Wall -Werror \
          -target bpf -D__TARGET_ARCH_x86

# Output directory
TARGET_DIR := ./target
OUTPUT_OBJ := $(TARGET_DIR)/xdp.o

# Source file
SRC_FILE := xdp.c

# Phony targets (targets that don't represent files)
.PHONY: all clean

# Default target: build the eBPF program
all: $(OUTPUT_OBJ)

# Rule to compile the C source to an eBPF object file
$(OUTPUT_OBJ): $(SRC_FILE) | $(TARGET_DIR)
	@echo "  CLANG  $(SRC_FILE) -> $@"
	$(CLANG) $(CFLAGS) -c $(SRC_FILE) -o $@

# Rule to create the target directory if it doesn't exist
$(TARGET_DIR):
	@echo "  MKDIR  $@"
	@mkdir -p $(TARGET_DIR)

# Clean up build artifacts
clean:
	@echo "  CLEAN"
	$(RM) $(TARGET_DIR)