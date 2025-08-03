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

# Export variables for use in sourcing scripts
export script_path
export script_dir
export root_path
export artifacts_dir