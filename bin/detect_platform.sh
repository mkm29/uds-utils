#!/bin/bash
# platform-detect - Detect OS and CPU architecture
# Returns platform string combining OS + CPU architecture

# Get operating system
get_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    case "$os" in
        linux)   echo "linux" ;;
        darwin)  echo "darwin" ;;    # macOS
        mingw*|msys*|cygwin*) echo "windows" ;;
        *)       echo "$os" ;;
    esac
}

# Get CPU architecture
get_arch() {
    local arch=$(uname -m)
    
    case "$arch" in
        x86_64|amd64)    echo "amd64" ;;     # Intel/AMD 64-bit
        aarch64|arm64)   echo "arm64" ;;     # ARM 64-bit
        armv7l|armv7)    echo "arm" ;;       # ARM 32-bit
        i386|i686)       echo "386" ;;       # Intel/AMD 32-bit
        *)               echo "$arch" ;;
    esac
}

# Get combined platform string
get_platform() {
    echo "$(get_os)-$(get_arch)"
}

# Main
case "${1:-}" in
    os|--os)
        get_os
        ;;
    arch|--arch)
        get_arch
        ;;
    -s|--separate)
        echo "OS: $(get_os)"
        echo "Architecture: $(get_arch)"
        ;;
    -d|--detailed)
        os_raw=$(uname -s)
        arch_raw=$(uname -m)
        os=$(get_os)
        arch=$(get_arch)
        
        echo "Raw OS: $os_raw"
        echo "Raw Architecture: $arch_raw"
        echo "Normalized OS: $os"
        echo "Normalized Architecture: $arch"
        echo "Platform String: ${os}-${arch}"
        ;;
    -h|--help)
        cat <<EOF
Usage: $(basename $0) [OPTIONS]

Detect operating system and CPU architecture.

Options:
  os, --os          Show only the operating system
  arch, --arch      Show only the CPU architecture
  -s, --separate    Show OS and architecture separately
  -d, --detailed    Show detailed information
  -h, --help        Show this help

Default: Output platform string (e.g., linux-amd64, darwin-arm64)

Examples:
  $(basename $0)              # Output: linux-amd64
  $(basename $0) --os         # Output: linux
  $(basename $0) --arch       # Output: amd64
  $(basename $0) --separate   # Output: OS: linux
                              #         Architecture: amd64

Common platforms:
  linux-amd64    - Linux on Intel/AMD 64-bit
  linux-arm64    - Linux on ARM 64-bit (RPi 4, AWS Graviton)
  darwin-amd64   - macOS on Intel
  darwin-arm64   - macOS on Apple Silicon (M1/M2/M3)
  windows-amd64  - Windows on Intel/AMD 64-bit
EOF
        ;;
    *)
        get_platform
        ;;
esac

export -f get_os
export -f get_arch
export -f get_platform