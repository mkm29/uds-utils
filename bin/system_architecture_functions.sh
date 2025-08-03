#!/bin/bash
# system-arch-functions.sh - System architecture detection utilities
#
# Installation:
#   1. As sourced functions: source this file in .bashrc/.zshrc
#   2. As executable: place in PATH and run with 'system-arch-functions <function>'

# Helper function to detect system architecture
get_system_arch() {
	local os arch

	# Get OS type (linux, darwin, windows)
	os=$(uname -s | tr '[:upper:]' '[:lower:]')

	# Handle special cases
	case "$os" in
	"mingw"* | "msys"* | "cygwin"*)
		os="windows"
		;;
	esac

	# Get architecture
	arch=$(uname -m)

	# Normalize architecture names
	case "$arch" in
	"x86_64" | "amd64")
		arch="amd64"
		;;
	"aarch64" | "arm64")
		arch="arm64"
		;;
	"armv7l" | "armv7")
		arch="arm"
		;;
	"i386" | "i686")
		arch="386"
		;;
	*)
		# Keep original if not recognized
		;;
	esac

	# Return in format: os-arch
	echo "${os}-${arch}"
}

# Extended version with more details
get_system_arch_detailed() {
	local os arch os_pretty arch_bits

	# Get OS type
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	os_pretty=$(uname -s)

	# Get architecture
	arch=$(uname -m)

	# Detect bit size
	arch_bits=$(getconf LONG_BIT 2>/dev/null || echo "unknown")

	# Normalize OS names
	case "$os" in
	"linux")
		os_pretty="Linux"
		# Try to detect distribution
		if [ -f /etc/os-release ]; then
			distro=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]' | awk '{print $1}')
			os_pretty="Linux ($distro)"
		fi
		;;
	"darwin")
		os_pretty="macOS"
		# Get macOS version if available
		if command -v sw_vers >/dev/null 2>&1; then
			mac_ver=$(sw_vers -productVersion)
			os_pretty="macOS $mac_ver"
		fi
		;;
	"mingw"* | "msys"* | "cygwin"*)
		os="windows"
		os_pretty="Windows"
		;;
	esac

	# Normalize architecture names
	case "$arch" in
	"x86_64" | "amd64")
		arch="amd64"
		arch_pretty="x86_64 (${arch_bits}-bit)"
		;;
	"aarch64" | "arm64")
		arch="arm64"
		arch_pretty="ARM64 (${arch_bits}-bit)"
		;;
	"armv7l" | "armv7")
		arch="arm"
		arch_pretty="ARMv7 (32-bit)"
		;;
	"i386" | "i686")
		arch="386"
		arch_pretty="x86 (32-bit)"
		;;
	*)
		arch_pretty="$arch"
		;;
	esac

	# Return detailed info
	cat <<EOF
System: $os_pretty
Architecture: $arch_pretty
Platform String: ${os}-${arch}
EOF
}

# Function to validate if architecture is supported
is_arch_supported() {
	local arch="$1"
	local supported_archs=("linux-amd64" "linux-arm64" "linux-arm" "linux-386"
		"darwin-amd64" "darwin-arm64"
		"windows-amd64" "windows-arm64" "windows-386")

	for supported in "${supported_archs[@]}"; do
		if [ "$arch" = "$supported" ]; then
			return 0
		fi
	done
	return 1
}

# Auto-detect with fallback
get_arch_with_fallback() {
	local detected fallback="$1"
	detected=$(get_system_arch)

	if is_arch_supported "$detected"; then
		echo "$detected"
	else
		echo "${fallback:-linux-amd64}"
	fi
}

# Export functions if being sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
	export -f get_system_arch
	export -f get_system_arch_detailed
	export -f is_arch_supported
	export -f get_arch_with_fallback
else
	# Script is being executed directly
	case "${1:-}" in
	"get_system_arch")
		get_system_arch
		;;
	"get_system_arch_detailed" | "detailed")
		get_system_arch_detailed
		;;
	"is_arch_supported")
		if [ -z "$2" ]; then
			echo "Usage: $0 is_arch_supported <arch>"
			exit 1
		fi
		if is_arch_supported "$2"; then
			echo "✓ Architecture '$2' is supported"
			exit 0
		else
			echo "✗ Architecture '$2' is not supported"
			exit 1
		fi
		;;
	"get_arch_with_fallback" | "fallback")
		get_arch_with_fallback "${2:-linux-amd64}"
		;;
	*)
		cat <<EOF
System Architecture Detection Utilities

Usage: 
  As executable:     $0 <function> [args]
  As source:         source $0

Available functions:
  get_system_arch              - Get system architecture (e.g., linux-amd64)
  get_system_arch_detailed     - Get detailed system information
  is_arch_supported <arch>     - Check if architecture is supported
  get_arch_with_fallback [fb]  - Get arch with fallback if unsupported

Examples:
  $0 get_system_arch
  $0 detailed
  $0 is_arch_supported darwin-arm64
  $0 fallback linux-386

Current system: $(get_system_arch)
EOF
		;;
	esac
fi

export -f get_system_arch
export -f get_system_arch_detailed
