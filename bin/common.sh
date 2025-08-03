#!/usr/bin/env bash

# common.sh - Common setup variables and functions for uds-utils scripts

# Get the absolute path of the script being executed
script_path="$(realpath "${BASH_SOURCE[0]}")"

# Get the directory containing the scripts (bin directory)
script_dir="$(dirname "$script_path")"

# Get the root directory of the project (parent of bin)
root_path="$(dirname "$script_dir")"

# Define common directories
artifacts_dir="${root_path}/artifacts"

# Create artifacts directory if it doesn't exist
mkdir -p "$artifacts_dir"

# Color variables for consistent output
RED=$(tput setaf 1 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
PINK=$(tput setaf 5 2>/dev/null || echo "")
CYAN=$(tput setaf 6 2>/dev/null || echo "")
WHITE=$(tput setaf 7 2>/dev/null || echo "")
NC='\e[0m'

# Export color variables
export RED GREEN YELLOW BLUE PINK CYAN WHITE NC

# Common utility functions for consistent output
info() {
	echo -e "${BLUE}[INFO]  ${WHITE}$1${NC}" >&2
}

error() {
	echo -e "${RED}[ERROR] ${WHITE}$1${NC}" >&2
}

success() {
	echo -e "${GREEN}[OK]    ${WHITE}$1${NC}"
}

warning() {
	echo -e "${YELLOW}[WARN]  ${WHITE}$1${NC}" >&2
}

debug() {
	if [[ "${DEBUG:-0}" == "1" ]]; then
		echo -e "${CYAN}[DEBUG] ${WHITE}$1${NC}" >&2
	fi
}

# Additional color functions for scan output
blue() {
	echo -e "\033[1;34m$1\033[0m"
}

green() {
	echo -e "\033[0;32m$1\033[0m"
}

yellow() {
	echo -e "\033[0;33m$1\033[0m"
}

white() {
	echo -e "\033[0;37m$1\033[0m"
}

# Function to print without newline
blue_no_newline() {
	echo -en "\033[1;34m$1\033[0m"
}

green_no_newline() {
	echo -en "\033[0;32m$1\033[0m"
}

yellow_no_newline() {
	echo -en "\033[0;33m$1\033[0m"
}

white_no_newline() {
	echo -en "\033[0;37m$1\033[0m"
}


# Argument parsing helper functions
has_argument() {
	[[ ("$1" == *=* && -n ${1#*=}) || ( -n "$2" && "$2" != -*) ]]
}

extract_argument() {
	echo "${2:-${1#*=}}"
}

# Platform detection functions
# Get operating system
get_os() {
	local os
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	
	case "$os" in
		linux)   echo "linux" ;;
		darwin)  echo "darwin" ;;    # macOS
		mingw*|msys*|cygwin*) echo "windows" ;;
		*)       echo "$os" ;;
	esac
}

# Get CPU architecture
get_arch() {
	local arch
	arch=$(uname -m)
	
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

# Function to check if a command exists
command_exists() {
	command -v "$1" >/dev/null 2>&1
}

# Function to install a package using the appropriate package manager
install_package() {
	local package="$1"
	
	if [ -z "$package" ]; then
		error "Package name is required"
		return 1
	fi
	
	info "Installing $package..."
	
	if command_exists apt-get; then
		sudo apt-get update && sudo apt-get install -y "$package"
	elif command_exists yum; then
		sudo yum install -y "$package"
	elif command_exists dnf; then
		sudo dnf install -y "$package"
	elif command_exists pacman; then
		sudo pacman -S --noconfirm "$package"
	elif command_exists zypper; then
		sudo zypper install -y "$package"
	elif command_exists brew; then
		brew install "$package"
	else
		error "No supported package manager found"
		return 1
	fi
}

# Function to login to a registry using zarf tools
login_registry() {
	local username="$1"
	local password="$2"
	local url="$3"
	
	# Validate arguments
	if [[ -z "$username" || -z "$password" || -z "$url" ]]; then
		error "login_registry requires 3 arguments: username, password, and URL"
		return 1
	fi
	
	# Login using password via stdin for security
	if echo "$password" | zarf tools registry login -u "$username" --password-stdin "$url" >/dev/null 2>&1; then
		success "Successfully logged into registry: $url"
		return 0
	else
		error "Failed to login to registry: $url"
		return 1
	fi
}

# Export variables for use in sourcing scripts
export UDS_URL="registry.defenseunicorns.com"
export IRONBANK_URL="registry1.dso.mil"
export script_path
export script_dir
export root_path
export artifacts_dir
