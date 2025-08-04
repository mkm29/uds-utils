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
	echo -e "${GREEN}[OK]    ${WHITE}$1${NC}" >&2
}

warning() {
	echo -e "${YELLOW}[WARN]  ${WHITE}$1${NC}" >&2
}

debug() {
	if [[ "${DEBUG:-0}" == "1" ]]; then
		echo -e "${CYAN}[DEBUG] ${WHITE}$1${NC}\n" >&2
	fi
}

# Additional color functions for scan output
blue() {
	echo -e "\033[1;34m$1\033[0m\n" >&2
}

green() {
	echo -e "\033[0;32m$1\033[0m\n" >&2
}

yellow() {
	echo -e "\033[0;33m$1\033[0m\n" >&2
}

white() {
	echo -e "\033[0;37m$1\033[0m\n" >&2
}

# Function to print without newline
blue_no_newline() {
	echo -en "\033[1;34m$1\033[0m" >&2
}

green_no_newline() {
	echo -en "\033[0;32m$1\033[0m" >&2
}

yellow_no_newline() {
	echo -en "\033[0;33m$1\033[0m" >&2
}

white_no_newline() {
	echo -en "\033[0;37m$1\033[0m" >&2
}

# Argument parsing helper functions
has_argument() {
	[[ ("$1" == *=* && -n ${1#*=}) || (-n "$2" && "$2" != -*) ]]
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
	linux) echo "linux" ;;
	darwin) echo "darwin" ;; # macOS
	mingw* | msys* | cygwin*) echo "windows" ;;
	*) echo "$os" ;;
	esac
}

# Get CPU architecture
get_arch() {
	local arch
	arch=$(uname -m)

	case "$arch" in
	x86_64 | amd64) echo "amd64" ;;  # Intel/AMD 64-bit
	aarch64 | arm64) echo "arm64" ;; # ARM 64-bit
	armv7l | armv7) echo "arm" ;;    # ARM 32-bit
	i386 | i686) echo "386" ;;       # Intel/AMD 32-bit
	*) echo "$arch" ;;
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

# Function to extract an OCI image from a package archive
extract_oci_image() {
	local package_archive="$1"
	local manifest_digest="$2"
	local target_dir="$3"

	# Validate arguments
	if [[ -z "$package_archive" || -z "$manifest_digest" || -z "$target_dir" ]]; then
		error "extract_oci_image requires 3 arguments: package_archive, manifest_digest, target_dir"
		return 1
	fi

	# Check if package archive exists
	if [[ ! -f "$package_archive" ]]; then
		error "Package archive not found: $package_archive"
		return 1
	fi

	# Create a temporary directory for extraction
	local temp_extract_dir
	temp_extract_dir=$(mktemp -d)
	trap 'rm -rf "$temp_extract_dir"' RETURN

	# Extract the package archive
	info "Extracting package archive: $package_archive"
	if ! tar -xf "$package_archive" -C "$temp_extract_dir" 2>/dev/null; then
		error "Failed to extract package archive"
		return 1
	fi

	# Check if images directory exists
	local images_dir="$temp_extract_dir/images"
	if [[ ! -d "$images_dir" ]]; then
		error "Images directory not found in package archive"
		return 1
	fi

	# Create target directory structure
	mkdir -p "$target_dir/blobs/sha256"

	# Copy oci-layout
	if [[ -f "$images_dir/oci-layout" ]]; then
		cp "$images_dir/oci-layout" "$target_dir/"
	else
		error "oci-layout not found in images directory"
		return 1
	fi

	# Extract the digest without sha256: prefix
	local digest_hash="${manifest_digest#sha256:}"

	# Copy the manifest
	if [[ -f "$images_dir/blobs/sha256/$digest_hash" ]]; then
		cp "$images_dir/blobs/sha256/$digest_hash" "$target_dir/blobs/sha256/"
	else
		error "Manifest not found: $manifest_digest"
		return 1
	fi

	# Parse manifest to get config and layer digests
	local manifest_content
	manifest_content=$(cat "$images_dir/blobs/sha256/$digest_hash")

	# Extract config digest
	local config_digest
	config_digest=$(echo "$manifest_content" | jq -r '.config.digest')
	if [[ -n "$config_digest" && "$config_digest" != "null" ]]; then
		local config_hash="${config_digest#sha256:}"
		if [[ -f "$images_dir/blobs/sha256/$config_hash" ]]; then
			cp "$images_dir/blobs/sha256/$config_hash" "$target_dir/blobs/sha256/"
		else
			warning "Config blob not found: $config_digest"
		fi
	fi

	# Extract and copy all layers
	echo "$manifest_content" | jq -r '.layers[].digest' 2>/dev/null | while read -r layer_digest; do
		if [[ -n "$layer_digest" && "$layer_digest" != "null" ]]; then
			local layer_hash="${layer_digest#sha256:}"
			if [[ -f "$images_dir/blobs/sha256/$layer_hash" ]]; then
				cp "$images_dir/blobs/sha256/$layer_hash" "$target_dir/blobs/sha256/"
			else
				warning "Layer blob not found: $layer_digest"
			fi
		fi
	done

	# Create index.json with single manifest
	local media_type
	media_type=$(echo "$manifest_content" | jq -r '.mediaType // "application/vnd.docker.distribution.manifest.v2+json"')

	# Get the size of the manifest file
	local manifest_size
	if [[ "$(get_os)" == "darwin" ]]; then
		manifest_size=$(stat -f%z "$images_dir/blobs/sha256/$digest_hash" 2>/dev/null || echo "0")
	else
		manifest_size=$(stat -c%s "$images_dir/blobs/sha256/$digest_hash" 2>/dev/null || echo "0")
	fi

	cat >"$target_dir/index.json" <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "$media_type",
      "digest": "$manifest_digest",
      "size": $manifest_size
    }
  ]
}
EOF

	success "Successfully extracted OCI image to: $target_dir"
	return 0
}

# Function to extract all OCI images from a package archive
extract_all_oci_images() {
	local package_archive="$1"
	local output_base_dir="$2"

	# Validate arguments
	if [[ -z "$package_archive" || -z "$output_base_dir" ]]; then
		error "extract_all_oci_images requires 2 arguments: package_archive, output_base_dir"
		return 1
	fi

	# Check if package archive exists
	if [[ ! -f "$package_archive" ]]; then
		error "Package archive not found: $package_archive"
		return 1
	fi

	# Create output directory
	mkdir -p "$output_base_dir"

	# Create a temporary directory for extraction
	local temp_extract_dir
	temp_extract_dir=$(mktemp -d)
	trap 'rm -rf "$temp_extract_dir"' RETURN

	# Extract the package archive
	info "Extracting package archive for image discovery: $package_archive"
	if ! tar -xf "$package_archive" -C "$temp_extract_dir" 2>/dev/null; then
		error "Failed to extract package archive"
		return 1
	fi

	# Check if images directory exists
	local images_dir="$temp_extract_dir/images"
	if [[ ! -d "$images_dir" ]]; then
		error "Images directory not found in package archive"
		return 1
	fi

	# Check if index.json exists
	local index_file="$images_dir/index.json"
	if [[ ! -f "$index_file" ]]; then
		error "index.json not found in images directory"
		return 1
	fi

	# Parse index.json to get all manifest digests
	local manifests
	manifests=$(jq -r '.manifests[].digest' "$index_file" 2>/dev/null)

	if [[ -z "$manifests" ]]; then
		error "No manifests found in index.json"
		return 1
	fi

	# Extract each image
	local count=0
	local extracted_info=()

	# Parse index.json to get manifest information with annotations
	local manifest_count
	manifest_count=$(jq '.manifests | length' "$index_file" 2>/dev/null || echo 0)

	local i
	for ((i = 0; i < manifest_count; i++)); do
		local manifest_digest
		manifest_digest=$(jq -r ".manifests[$i].digest" "$index_file" 2>/dev/null)

		# Extract image name from annotations - try multiple fields
		local image_name

		# Try org.opencontainers.image.ref.name first (full reference)
		image_name=$(jq -r ".manifests[$i].annotations.\"org.opencontainers.image.ref.name\" // empty" "$index_file" 2>/dev/null)

		# If not found, try base name
		if [[ -z "$image_name" ]]; then
			image_name=$(jq -r ".manifests[$i].annotations.\"org.opencontainers.image.base.name\" // empty" "$index_file" 2>/dev/null)
		fi

		# Try other common annotation fields
		if [[ -z "$image_name" ]]; then
			image_name=$(jq -r ".manifests[$i].annotations.\"com.github.package.name\" // empty" "$index_file" 2>/dev/null)
		fi

		# Try io.k8s.display-name
		if [[ -z "$image_name" ]]; then
			image_name=$(jq -r ".manifests[$i].annotations.\"io.k8s.display-name\" // empty" "$index_file" 2>/dev/null)
		fi

		# Debug: print all annotations for this manifest
		if [[ "${DEBUG:-0}" == "1" ]]; then
			echo "DEBUG: Annotations for manifest $i:" >&2
			jq ".manifests[$i].annotations // {}" "$index_file" >&2
		fi

		if [[ -n "$manifest_digest" && "$manifest_digest" != "null" ]]; then
			count=$((count + 1))
			local image_dir="$output_base_dir/image_$count"

			info "Extracting image $count with manifest: $manifest_digest"
			if [[ -n "$image_name" ]]; then
				info "  Image name: $image_name"
			fi

			if extract_oci_image "$package_archive" "$manifest_digest" "$image_dir"; then
				# Return both directory and image name as tab-separated values
				if [[ -n "$image_name" ]]; then
					extracted_info+=("${image_dir}	${image_name}")
				else
					extracted_info+=("${image_dir}	unknown")
				fi
			else
				warning "Failed to extract image with manifest: $manifest_digest"
			fi
		fi
	done

	success "Extracted $count OCI images from package"

	# Return the list of extracted directories with image names (to stdout)
	# Make sure success message went to stderr
	for item in "${extracted_info[@]}"; do
		echo "$item"
	done
	return 0
}

# Export variables for use in sourcing scripts
export UDS_URL="registry.defenseunicorns.com"
export IRONBANK_URL="registry1.dso.mil"
export script_path
export script_dir
export root_path
export artifacts_dir
