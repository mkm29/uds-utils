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

# Common utility functions for consistent output
info() {
	echo -e "\033[1;34m$1\033[0m"
}

error() {
	echo -e "\033[1;31mError: $1\033[0m" >&2
}

success() {
	echo -e "\033[0;32m$1\033[0m"
}

warning() {
	echo -e "\033[0;33m$1\033[0m"
}

debug() {
	if [[ "${DEBUG:-0}" == "1" ]]; then
		echo -e "\033[0;36mDebug: $1\033[0m" >&2
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
