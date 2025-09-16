#!/usr/bin/env bash

set -uo pipefail # Remove -e to prevent early exit

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
REGISTRY="${REGISTRY:-registry.defenseunicorns.com}"
ORG="${ORG:-sld-45}"
ARCH="${ARCH:-amd64}"
PACKAGES_FILE="${1:-${PROJECT_ROOT}/packages.txt}"

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

log_debug() {
	echo -e "${YELLOW}[DEBUG]${NC} $1"
}

# Function to clean up SBOM filename - remove registry and org prefixes
clean_sbom_filename() {
	local filename="$1"
	# Remove .json extension first
	local base="${filename%.json}"

	# Remove common registry prefixes (handles dots converted to underscores)
	local cleaned="$base"
	cleaned=$(echo "$cleaned" | sed -E 's/^(quay_io_|docker_io_|ghcr_io_|registry[^_]*_|gcr_io_)//g')

	# Remove organization/namespace that typically follows the registry
	cleaned=$(echo "$cleaned" | sed -E 's/^[a-z0-9]+_//g')

	# Return with .json extension
	echo "${cleaned}.json"
}

# Check that prereqs are installed
for cmd in uds grype jq; do
	if ! command -v "$cmd" &>/dev/null; then
		log_error "$cmd could not be found, please install $cmd to proceed."
		exit 1
	fi
done

# Create a temporary directory for processing
log_info "Creating temporary working directory..."
WORK_DIR=$(mktemp -d)
log_info "Working directory created at $WORK_DIR"
mkdir -p "${WORK_DIR}/reports"
mkdir -p "${WORK_DIR}/temp_reports"

# Create a trap to clean up the temporary directory on exit
trap 'rm -rf "$WORK_DIR"' EXIT

# Read packages file
log_info "Reading packages from ${PACKAGES_FILE}..."
if [ ! -f "$PACKAGES_FILE" ]; then
	log_error "Packages file not found: $PACKAGES_FILE"
	exit 1
fi

mapfile -t PACKAGES <"$PACKAGES_FILE"
if [ ${#PACKAGES[@]} -eq 0 ]; then
	log_error "No packages found in $PACKAGES_FILE"
	exit 1
fi
log_info "Found ${#PACKAGES[@]} packages to scan."

# Track statistics
total_sboms_scanned=0
total_reports_created=0
failed_packages=0
successful_packages=0

# Process each package
for pkg in "${PACKAGES[@]}"; do
	log_info "Processing package: $pkg"

	# Create directory for this package's SBOMs
	pkg_dir="${WORK_DIR}/$(echo "$pkg" | tr '/:' '__')"
	mkdir -p "$pkg_dir"

	# Download SBOMs for the package
	log_debug "  Running: uds zarf package inspect sbom \"oci://${REGISTRY}/${ORG}/${pkg}\" -a \"${ARCH}\" --output \"${pkg_dir}\""

	if ! uds zarf package inspect sbom "oci://${REGISTRY}/${ORG}/${pkg}" -a "${ARCH}" --output "${pkg_dir}"; then
		log_warn "  Failed to pull SBOMs for: $pkg. Skipping..."
		((failed_packages++))
		continue
	fi

	# Check if any JSON files were actually created
	json_count=$(find "${pkg_dir}" -type f -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
	log_debug "  Found $json_count SBOM JSON files in ${pkg_dir}"

	if [ "$json_count" -eq 0 ]; then
		log_warn "  No SBOM JSON files found for $pkg"
		((failed_packages++))
		continue
	fi

	# Create safe package name for report naming
	pkg_safe=$(echo "$pkg" | tr '/:' '_')

	# Create temporary directory for this package's individual reports
	pkg_temp_dir="${WORK_DIR}/temp_reports/${pkg_safe}"
	mkdir -p "$pkg_temp_dir"

	# Reset array for this package
	unset report_files
	declare -a report_files=()

	# Scan each SBOM JSON file found
	sbom_count=0
	while IFS= read -r -d '' sbom; do
		# Get the original filename
		original_filename=$(basename "${sbom}")

		# Clean the filename to create report name
		cleaned_filename=$(clean_sbom_filename "$original_filename")

		# Create report name for individual SBOM
		temp_report_path="${pkg_temp_dir}/${cleaned_filename}"

		log_info "  Scanning SBOM: ${original_filename}"

		# Run Grype scan and save as JSON (allow it to fail)
		if grype sbom:"${sbom}" -o json --file "$temp_report_path" 2>/dev/null; then
			log_debug "    Grype completed successfully"
		else
			log_debug "    Grype found vulnerabilities or encountered an error"
		fi

		# Check if report was created
		if [ -f "$temp_report_path" ]; then
			log_info "    Created temp report: ${cleaned_filename}"
			report_files+=("$temp_report_path")
			((sbom_count++))
		else
			log_warn "    Failed to create report for: ${original_filename}"
		fi

		((total_sboms_scanned++))
	done < <(find "${pkg_dir}" -type f -name "*.json" -print0)

	# Merge all reports for this package
	if [ ${#report_files[@]} -gt 0 ]; then
		merged_report="${WORK_DIR}/reports/${pkg_safe}.json"

		if [ ${#report_files[@]} -eq 1 ]; then
			# Only one report, just copy it
			log_info "  Single SBOM found, copying report..."
			cp "${report_files[0]}" "$merged_report"
		else
			# Multiple reports - merge them using jq
			log_info "  Merging ${#report_files[@]} SBOM reports for $pkg..."

			# Merge all matches arrays and preserve other metadata from the first report
			if jq -s '
				# Take the first report as the base
				.[0] as $base |
				# Collect all matches from all reports
				[.[] | .matches // []] | flatten as $all_matches |
				# Merge into base structure, replacing matches with combined array
				$base | .matches = $all_matches
			' "${report_files[@]}" >"$merged_report" 2>/dev/null; then
				# Count total vulnerabilities in merged report
				vuln_count=$(jq '.matches | length' "$merged_report" 2>/dev/null || echo "0")
				log_info "  Merged report contains $vuln_count total vulnerabilities"
			else
				log_error "  Failed to merge reports with jq"
			fi
		fi

		if [ -f "$merged_report" ]; then
			log_info "  Successfully created merged report: ${pkg_safe}.json"
			((total_reports_created++))
			((successful_packages++))
		else
			log_error "  Failed to create merged report for $pkg"
		fi

		# Clean up temporary reports
		rm -rf "$pkg_temp_dir"
	else
		log_warn "  No SBOMs successfully scanned for $pkg"
	fi

	log_info "  Finished processing $pkg"
	log_info ""
done

# Clean up all temporary directories
rm -rf "${WORK_DIR}/temp_reports"

# Check if any reports were created
if [ $total_reports_created -eq 0 ]; then
	log_error "No reports were generated."
	exit 1
fi

# Optional: Create a master JSON report with all vulnerabilities from all packages
log_info "Creating master vulnerability report..."
master_report="${WORK_DIR}/reports/ALL_VULNERABILITIES.json"

# Collect all package reports
all_reports=()
for report in "${WORK_DIR}/reports"/*.json; do
	if [ "$report" != "$master_report" ] && [ -f "$report" ]; then
		all_reports+=("$report")
	fi
done

if [ ${#all_reports[@]} -gt 0 ]; then
	# Merge all package reports into one master report
	if jq -s '
		# Take metadata from first report
		.[0] as $base |
		# Collect all matches from all reports
		[.[] | .matches // []] | flatten as $all_matches |
		# Create master report with combined matches
		$base | .matches = $all_matches
	' "${all_reports[@]}" >"$master_report" 2>/dev/null; then
		total_vulns=$(jq '.matches | length' "$master_report" 2>/dev/null || echo "0")
		log_info "Master report contains $total_vulns total vulnerabilities across all packages"
	else
		log_warn "Failed to create master report"
	fi
fi

# Create tarball of all reports
log_info ""
log_info "Creating tarball of all Grype reports..."
tar czf "${PROJECT_ROOT}/zarf-scan-reports.tar.gz" -C "${WORK_DIR}" reports/
log_info "Reports tarball created at ${PROJECT_ROOT}/zarf-scan-reports.tar.gz"

# Print summary
log_info ""
log_info "========== Summary =========="
log_info "Total packages: ${#PACKAGES[@]}"
log_info "Successful packages: $successful_packages"
log_info "Failed packages: $failed_packages"
log_info "Total SBOMs found: $total_sboms_scanned"
log_info "Total package reports created: $total_reports_created"
log_info ""
log_info "Output: ${PROJECT_ROOT}/zarf-scan-reports.tar.gz"

exit 0
