# Makefile for XDP program

# Compiler and flags
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Output directory
OUTPUT := ./build

# BPF compiler flags
BPF_CFLAGS ?= -g -O2 -Wall -Werror

# Source and object files
XDP_SRC := $(wildcard *.c)
XDP_OBJ := $(patsubst %.c, $(OUTPUT)/%.o, $(XDP_SRC))

# Default target
all: $(OUTPUT) $(XDP_OBJ)

# Create build directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile XDP/BPF program
$(OUTPUT)/%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -target bpf -D__BPF_TRACING__ -c $< -o $@
	$(LLVM_STRIP) -g $@

# Clean
clean:
	rm -rf $(OUTPUT)

# Install XDP program to specified network interface
# Usage: make install IFACE=enp0s8
IFACE ?= enp0s8
install: all
	@if [ -z "$(IFACE)" ]; then \
		echo "Error: Network interface not specified."; \
		echo "Usage: make install IFACE=<interface_name>"; \
		exit 1; \
	fi
	@echo "Installing XDP program to interface $(IFACE)..."
	@for obj in $(XDP_OBJ); do \
		echo "Loading $$obj to $(IFACE)..."; \
		ip link set dev $(IFACE) xdp obj $$obj || \
		(echo "Failed to load XDP program. Make sure you have permissions and the interface exists." && exit 1); \
	done
	@echo "XDP program successfully loaded to $(IFACE)"

# Uninstall XDP program from specified network interface
uninstall:
	@if [ -z "$(IFACE)" ]; then \
		echo "Error: Network interface not specified."; \
		echo "Usage: make uninstall IFACE=<interface_name>"; \
		exit 1; \
	fi
	@echo "Removing XDP program from interface $(IFACE)..."
	ip link set dev $(IFACE) xdp off
	@echo "XDP program successfully unloaded from $(IFACE)"

.PHONY: all clean install uninstall