#!/usr/bin/env bash

# Configuration
REGISTRY="${REGISTRY:-registry.defenseunicorns.com}"
ORG="${ORG:-sld-45}"
ARCH="${ARCH:-amd64}"
PACKAGES_FILE="${1:-../packages.txt}"

# Directories
PACKAGES_DIR="./packages"
REPORTS_DIR="./reports"
EXTRACTED_DIR="./extracted"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1"
}

# Function to pull and unpack a package
pull_and_unpack_package() {
	local repo=$1
	local flavor=$2
	local version=$3

	# Construct package file name and OCI URL based on whether flavor exists
	local package_file
	local oci_url

	if [ "$repo" == "init" ]; then
		# Special case for init package - uses different naming convention
		package_file="zarf-init-${ARCH}-${version}.tar.zst"
		oci_url="oci://${REGISTRY}/${ORG}/${repo}:${version}"
		log_info "Pulling ${repo} ${version} (special init package)..."
	elif [ -z "$flavor" ] || [ "$flavor" == "none" ]; then
		# No flavor - package format: zarf-package-{repo}-{arch}-{version}.tar.zst
		package_file="zarf-package-${repo}-${ARCH}-${version}.tar.zst"
		oci_url="oci://${REGISTRY}/${ORG}/${repo}:${version}"
		log_info "Pulling ${repo} ${version} (no flavor)..."
	else
		# With flavor - package format: zarf-package-{repo}-{arch}-{version}-{flavor}.tar.zst
		package_file="zarf-package-${repo}-${ARCH}-${version}-${flavor}.tar.zst"
		oci_url="oci://${REGISTRY}/${ORG}/${repo}:${version}-${flavor}"
		log_info "Pulling ${repo} ${version} (flavor: ${flavor})..."
	fi

	if ! zarf package pull "${oci_url}" -a ${ARCH}; then
		log_error "Failed to pull ${oci_url}"
		return 1
	fi

	log_info "Unpacking ${repo} package from ${package_file}..."
	if ! tar xzf "${package_file}" -C "${PACKAGES_DIR}"; then
		log_error "Failed to unpack ${package_file}"
		return 1
	fi

	# Clean up the tar file to save space
	rm -f "${package_file}"

	return 0
}

# Function to extract images from OCI artifact
extract_images() {
	local repo=$1
	local flavor=$2
	local version=$3
	local src_dir="${PACKAGES_DIR}/images"

	if [ ! -f "${src_dir}/index.json" ]; then
		log_error "index.json not found in ${src_dir}"
		return 1
	fi

	log_info "Extracting images from ${repo} OCI artifact..."
	local digests=$(jq -r '.manifests[].digest' "${src_dir}/index.json")

	for digest in $digests; do
		local image_name=$(jq -r --arg d "$digest" \
			'.manifests[] | select(.digest==$d) | .annotations."org.opencontainers.image.ref.name"' \
			"${src_dir}/index.json" | sed 's|.*/||' | sed 's|:|_|g')

		# Construct directory name based on whether flavor exists
		local dir_name
		if [ -z "$flavor" ] || [ "$flavor" == "none" ]; then
			dir_name="${EXTRACTED_DIR}/${repo}-${version}/${image_name}"
		else
			dir_name="${EXTRACTED_DIR}/${repo}-${flavor}-${version}/${image_name}"
		fi
		mkdir -p "$dir_name"

		log_info "  Extracting ${image_name}..."
		if ! oras copy --from-oci-layout --to-oci-layout "${src_dir}@${digest}" "${dir_name}:latest" &>/dev/null; then
			log_warn "  Failed to extract ${image_name}"
		fi
	done

	# Clean up the unpacked package to save space
	rm -rf "${PACKAGES_DIR}/images"

	return 0
}

# Function to scan extracted images
scan_images() {
	local repo=$1
	local flavor=$2
	local version=$3

	# Construct package directory based on whether flavor exists
	local package_dir
	if [ -z "$flavor" ] || [ "$flavor" == "none" ]; then
		package_dir="${EXTRACTED_DIR}/${repo}-${version}"
	else
		package_dir="${EXTRACTED_DIR}/${repo}-${flavor}-${version}"
	fi

	if [ ! -d "$package_dir" ]; then
		log_warn "No extracted images found for ${package_dir}"
		return 1
	fi

	local package_identifier
	if [ -z "$flavor" ] || [ "$flavor" == "none" ]; then
		package_identifier="${repo}-${version}"
	else
		package_identifier="${repo}-${flavor}-${version}"
	fi

	log_info "Scanning images from ${package_identifier}..."

	for dir in "$package_dir"/*; do
		if [ -d "$dir" ]; then
			local image_name=$(basename "$dir")
			local report_name="${package_identifier}-${image_name}"

			log_info "  Scanning ${image_name}..."
			if grype oci-dir:"$dir" -o json --file "${REPORTS_DIR}/${report_name}.json" &>/dev/null; then
				log_info "  Report saved: ${report_name}.json"
			else
				log_warn "  Failed to scan ${image_name}"
			fi
		fi
	done

	return 0
}

# Function to process a single package
process_package() {
	local package_line=$1
	local repo=""
	local flavor=""
	local version=""

	# Count the number of colons to determine the format
	local colon_count=$(echo "$package_line" | tr -cd ':' | wc -c)

	if [ $colon_count -eq 2 ]; then
		# Format: package:flavor:version
		IFS=':' read -r repo flavor version <<<"$package_line"
	elif [ $colon_count -eq 1 ]; then
		# Could be package::version (no flavor) or package:version (old format)
		if [[ "$package_line" == *"::"* ]]; then
			# Format: package::version (no flavor)
			IFS=':' read -r repo _ version <<<"$package_line"
			flavor=""
		else
			# Format: package:version (assume no flavor)
			IFS=':' read -r repo version <<<"$package_line"
			flavor=""
		fi
	else
		log_warn "Invalid package format: ${package_line}"
		log_warn "Expected formats:"
		log_warn "  package:flavor:version (e.g., gitlab-runner:unicorn:18.2.0-uds.0)"
		log_warn "  package::version (e.g., init::v0.61.0)"
		return 1
	fi

	# Validate parsed values
	if [ -z "$repo" ] || [ -z "$version" ]; then
		log_warn "Invalid package format: ${package_line} - missing repo or version"
		return 1
	fi

	# Display what we're processing
	if [ -z "$flavor" ]; then
		log_info "Processing ${repo}::${version} (no flavor)"
	else
		log_info "Processing ${repo}:${flavor}:${version}"
	fi

	if ! pull_and_unpack_package "$repo" "$flavor" "$version"; then
		return 1
	fi

	if ! extract_images "$repo" "$flavor" "$version"; then
		return 1
	fi

	if ! scan_images "$repo" "$flavor" "$version"; then
		return 1
	fi

	# Clean up extracted images to save space (optional)
	# if [ -z "$flavor" ]; then
	#     rm -rf "${EXTRACTED_DIR}/${repo}-${version}"
	# else
	#     rm -rf "${EXTRACTED_DIR}/${repo}-${flavor}-${version}"
	# fi

	return 0
}

# Function to generate summary statistics
generate_summary() {
	log_info "Computing summary statistics..."

	local summary_file="${REPORTS_DIR}/summary.json"
	local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

	# Create a JSON object to hold all summary data
	local summary_json=$(jq -n --arg timestamp "$timestamp" '{
        timestamp: $timestamp,
        overall: {},
        by_package: {},
        high_severity_count: 0
    }')

	# Overall summary
	echo -e "\n${GREEN}=== Overall Vulnerability Summary ===${NC}"
	local overall_summary=$(jq -s '
      map(.matches[]?) | 
      group_by(.vulnerability.severity) | 
      map({severity: .[0].vulnerability.severity, count: length}) |
      sort_by(.severity)
    ' ${REPORTS_DIR}/*.json 2>/dev/null || echo '[]')

	echo "$overall_summary" | jq '.'

	# Add overall summary to JSON
	summary_json=$(echo "$summary_json" | jq --argjson overall "$overall_summary" '.overall = $overall')

	# Per-package summary
	echo -e "\n${GREEN}=== Per-Package Summary ===${NC}"

	# Group reports by package
	declare -A package_reports

	for report in ${REPORTS_DIR}/*.json; do
		if [ -f "$report" ] && [ "$(basename "$report")" != "summary.json" ]; then
			local report_name=$(basename "$report" .json)
			# Extract package identifier (everything before the last hyphen-separated image name)
			local package_id=$(echo "$report_name" | rev | cut -d'-' -f2- | rev)

			if [ -z "${package_reports[$package_id]}" ]; then
				package_reports[$package_id]="$report"
			else
				package_reports[$package_id]="${package_reports[$package_id]} $report"
			fi
		fi
	done

	# Display and collect summary for each package
	local packages_json="{}"
	for package_id in "${!package_reports[@]}"; do
		echo -e "\n${YELLOW}Package: ${package_id}${NC}"

		local package_summary="{}"
		local images_json="{}"

		# Aggregate vulnerabilities across all images in the package
		echo "${package_reports[$package_id]}" | tr ' ' '\n' | while read report; do
			if [ -f "$report" ]; then
				local image_name=$(basename "$report" .json | sed "s/${package_id}-//")
				echo -e "  ${GREEN}Image: ${image_name}${NC}"

				local image_summary=$(jq '
                  .matches | 
                  group_by(.vulnerability.severity) | 
                  map({severity: .[0].vulnerability.severity, count: length}) |
                  sort_by(.severity)
                ' "$report" 2>/dev/null || echo '[]')

				echo "$image_summary" | sed 's/^/    /'

				# Add image summary to package JSON
				images_json=$(echo "$images_json" | jq --arg name "$image_name" --argjson summary "$image_summary" '.[$name] = $summary')
			fi
		done

		# Aggregate all vulnerabilities for this package
		local package_total=$(echo "${package_reports[$package_id]}" | tr ' ' '\n' | xargs -I {} cat {} 2>/dev/null | jq -s '
          map(.matches[]?) | 
          group_by(.vulnerability.severity) | 
          map({severity: .[0].vulnerability.severity, count: length}) |
          sort_by(.severity)
        ' || echo '[]')

		# Create package entry
		package_summary=$(jq -n --argjson total "$package_total" --argjson images "$images_json" '{
            total: $total,
            images: $images
        }')

		packages_json=$(echo "$packages_json" | jq --arg id "$package_id" --argjson summary "$package_summary" '.[$id] = $summary')
	done

	# Add packages to summary JSON
	summary_json=$(echo "$summary_json" | jq --argjson packages "$packages_json" '.by_package = $packages')

	# High severity count across all packages
	echo -e "\n${RED}=== High Severity Vulnerabilities ===${NC}"
	local high_count=$(jq -s '[.[]?.matches[]?.vulnerability | select(.severity == "High")] | length' ${REPORTS_DIR}/*.json 2>/dev/null || echo "0")
	echo "Total High severity vulnerabilities: ${high_count}"

	# Add high severity count to summary JSON
	summary_json=$(echo "$summary_json" | jq --arg high "$high_count" '.high_severity_count = ($high | tonumber)')

	# Add critical severity count
	local critical_count=$(jq -s '[.[]?.matches[]?.vulnerability | select(.severity == "Critical")] | length' ${REPORTS_DIR}/*.json 2>/dev/null || echo "0")
	summary_json=$(echo "$summary_json" | jq --arg critical "$critical_count" '.critical_severity_count = ($critical | tonumber)')

	# Add total vulnerability count
	local total_count=$(jq -s '[.[]?.matches[]?.vulnerability] | length' ${REPORTS_DIR}/*.json 2>/dev/null || echo "0")
	summary_json=$(echo "$summary_json" | jq --arg total "$total_count" '.total_vulnerability_count = ($total | tonumber)')

	# Write summary to file
	echo "$summary_json" | jq '.' >"$summary_file"
	log_info "Summary saved to ${summary_file}"
}

# Function to package reports into a tarball
package_reports() {
	if [ -d "${REPORTS_DIR}" ] && [ "$(ls -A ${REPORTS_DIR}/*.json 2>/dev/null)" ]; then
		log_info "Packaging vulnerability reports..."
		local timestamp=$(date +%Y%m%d_%H%M%S)
		local archive_name="vulnerability_reports_${timestamp}.tar.gz"

		if tar czf "${archive_name}" -C "${REPORTS_DIR}" .; then
			log_info "Reports packaged in ${archive_name}"
		else
			log_warn "Failed to package reports"
		fi
	fi
}

# Function to cleanup temporary files
cleanup() {
	log_info "Cleaning up temporary files..."
	rm -rf "${PACKAGES_DIR}" "${EXTRACTED_DIR}" "${REPORTS_DIR}" "zarf-*.tar.zst"
}

# Main execution
main() {
	# Check if packages file exists
	if [ ! -f "$PACKAGES_FILE" ]; then
		log_error "Packages file not found: $PACKAGES_FILE"
		echo "Usage: $0 [packages_file]"
		echo "Format: Each line should be one of:"
		echo "  package:flavor:version (e.g., gitlab-runner:unicorn:18.2.0-uds.0)"
		echo "  package::version (e.g., init::v0.61.0)"
		exit 1
	fi

	# Check for required tools
	for tool in zarf oras jq grype; do
		if ! command -v $tool &>/dev/null; then
			log_error "Required tool '$tool' is not installed"
			exit 1
		fi
	done

	# Create necessary directories
	mkdir -p "$PACKAGES_DIR" "$REPORTS_DIR" "$EXTRACTED_DIR"

	# Clear previous runs (optional - comment out to keep previous results)
	# rm -rf "${REPORTS_DIR}"/* "${EXTRACTED_DIR}"/* "${PACKAGES_DIR}"/*

	# Process each package
	local total_packages=0
	local successful_packages=0

	while IFS= read -r line || [ -n "$line" ]; do
		# Skip empty lines and comments
		[[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

		# Trim whitespace
		line=$(echo "$line" | xargs)

		((total_packages++))

		if process_package "$line"; then
			((successful_packages++))
		fi

		echo "" # Add spacing between packages
	done <"$PACKAGES_FILE"

	# Generate summary
	if [ $successful_packages -gt 0 ]; then
		generate_summary
		package_reports
	else
		log_warn "No packages were successfully processed"
	fi

	cleanup

	# Final report
	echo -e "\n${GREEN}=== Processing Complete ===${NC}"
	echo "Processed ${successful_packages}/${total_packages} packages successfully"
	echo "Reports saved in: ${REPORTS_DIR}"
	echo "Summary available at: ${REPORTS_DIR}/summary.json"

	# Exit with error if any packages failed
	[ $successful_packages -eq $total_packages ] && exit 0 || exit 1
}

# Run main function
main "$@"
