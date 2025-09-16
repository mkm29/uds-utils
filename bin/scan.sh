#!/usr/bin/env bash

set -euo pipefail

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
REGISTRY="${REGISTRY:-registry.defenseunicorns.com}"
ORG="${ORG:-sld-45}"
ARCH="${ARCH:-amd64}"
PACKAGES_FILE="${1:-${PROJECT_ROOT}/packages.txt}"

# create associative array for processed packages
declare -A PROCESSED_PACKAGES

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

# Function to clean up SBOM filename - remove registry and org prefixes
clean_sbom_filename() {
	local filename="$1"
	# Remove .json extension first (SBOMs are still JSON)
	local base="${filename%.json}"

	# Split by underscore and look for common registry patterns to remove
	# Common patterns: quay.io_, docker.io_, ghcr.io_, registry.*, etc.
	# This regex removes everything up to and including the first registry-like pattern
	local cleaned="$base"

	# Remove common registry prefixes (handles dots converted to underscores)
	cleaned=$(echo "$cleaned" | sed -E 's/^(quay_io_|docker_io_|ghcr_io_|registry[^_]*_|gcr_io_)//g')

	# Remove organization/namespace that typically follows the registry
	# This removes the first segment after registry removal if it looks like an org
	# (e.g., rfcurated_, defenseunicorns_, etc.)
	cleaned=$(echo "$cleaned" | sed -E 's/^[a-z0-9]+_//g')

	# Return with .csv extension for the report
	echo "${cleaned}.csv"
}

# check that prereqs are installed
for cmd in uds jq grype; do
	if ! command -v "$cmd" &>/dev/null; then
		log_error "$cmd could not be found, please install $cmd to proceed."
		exit 1
	fi
done

# create a temporary directory for processing
log_info "Creating temporary working directory..."
WORK_DIR=$(mktemp -d)
log_info "Working directory created at $WORK_DIR"
mkdir -p "${WORK_DIR}/reports"
mkdir -p "${WORK_DIR}/temp_reports"

# Create the Grype template file
cat >"${WORK_DIR}/csv.tmpl" <<'EOF'
{{- range .Matches -}}
"{{.Artifact.Name}}","{{.Artifact.Version}}","{{if .Vulnerability.Fix.Versions}}{{index .Vulnerability.Fix.Versions 0}}{{end}}","{{.Artifact.Type}}","{{.Vulnerability.ID}}","{{.Vulnerability.Severity}}"
{{ end -}}
EOF

# create a trap to clean up the temporary directory on exit
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR" || exit 1

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

# create directory for each package
for pkg in "${PACKAGES[@]}"; do
	pkg_dir="${WORK_DIR}/$(echo "$pkg" | tr '/:' '__')"
	mkdir -p "$pkg_dir"
	PROCESSED_PACKAGES["$pkg"]=0
done

# download SBOMS for each package
# example: zarf package inspect sbom oci://registry.defenseunicorns.com/sld-45/gitlab-runner:18.3.0-uds.0-registry1 -a amd64
for pkg in "${PACKAGES[@]}"; do
	log_info "Processing package: $pkg"
	pkg_dir="${WORK_DIR}/$(echo "$pkg" | tr '/:' '__')"

	if ! uds zarf package inspect sbom "oci://${REGISTRY}/${ORG}/${pkg}" -a "${ARCH}" --output "${pkg_dir}" &>/dev/null; then
		log_warn "Failed to pull package SBOMs: $pkg. Skipping..."
		continue
	fi

	# Create safe package name for the merged report
	pkg_safe=$(echo "$pkg" | tr '/:' '_')

	# Create temporary directory for this package's individual reports
	pkg_temp_dir="${WORK_DIR}/temp_reports/${pkg_safe}"
	mkdir -p "$pkg_temp_dir"

	# Array to hold all CSV files for this package
	declare -a csv_files=()

	# iterate over all JSON files in $pkg_dir and scan each with grype
	# Use find to locate all JSON files recursively
	while IFS= read -r -d '' sbom; do
		# Get the original filename
		original_filename=$(basename "${sbom}")

		# Clean the filename to remove registry/org prefixes and change extension to .csv
		cleaned_filename=$(clean_sbom_filename "$original_filename")

		log_info "  Scanning SBOM: ${original_filename}"

		# Save individual report to temp directory as CSV
		temp_report="${pkg_temp_dir}/${cleaned_filename}"
		grype sbom:"${sbom}" -o template -t "${WORK_DIR}/csv.tmpl" --file "$temp_report"

		# Add to array if file was created successfully and is not empty
		if [ -f "$temp_report" ] && [ -s "$temp_report" ]; then
			csv_files+=("$temp_report")
		fi

		PROCESSED_PACKAGES["$pkg"]=1
	done < <(find "${pkg_dir}" -type f -name "*.json" -print0)

	# Merge all CSV reports for this package into a single file
	if [ ${#csv_files[@]} -gt 0 ]; then
		merged_report="${WORK_DIR}/reports/${pkg_safe}.csv"

		log_info "  Merging ${#csv_files[@]} SBOM report(s) into: ${pkg_safe}.csv"

		# Create CSV header
		echo '"Package","Version","Fixed Version","Type","CVE ID","Severity"' >"$merged_report"

		# Concatenate all CSV files (they don't have headers due to the template)
		for csv_file in "${csv_files[@]}"; do
			if [ -s "$csv_file" ]; then # Only append if file is not empty
				cat "$csv_file" >>"$merged_report"
			fi
		done

		# Remove duplicate lines if any (keeping the header)
		temp_dedup="${merged_report}.tmp"
		head -n 1 "$merged_report" >"$temp_dedup"
		tail -n +2 "$merged_report" | sort -u >>"$temp_dedup"
		mv "$temp_dedup" "$merged_report"

		# Verify the merged file was created
		if [ -f "$merged_report" ]; then
			# Count vulnerabilities (minus the header line)
			vuln_count=$(($(wc -l <"$merged_report") - 1))
			log_info "  Successfully created merged report: $(basename "$merged_report")"
			log_info "  Total unique vulnerabilities found: $vuln_count"
		else
			log_error "  Failed to create merged report for $pkg"
		fi

		# Clean up temporary reports for this package
		rm -rf "$pkg_temp_dir"
	else
		log_warn "  No vulnerabilities found in SBOMs for $pkg"

		# Create an empty CSV with just headers for packages with no vulnerabilities
		merged_report="${WORK_DIR}/reports/${pkg_safe}.csv"
		echo '"Package","Version","Fixed Version","Type","CVE ID","Severity"' >"$merged_report"
		echo "No vulnerabilities found" >>"$merged_report"
	fi
done

# Clean up all temporary directories
rm -rf "${WORK_DIR}/temp_reports"

# Check if any reports were created
if [ -z "$(ls -A "${WORK_DIR}/reports" 2>/dev/null)" ]; then
	log_error "No reports were generated."
	exit 1
fi

# Optional: Create a master CSV with all vulnerabilities from all packages
log_info "Creating master vulnerability report..."
master_report="${WORK_DIR}/reports/ALL_VULNERABILITIES.csv"
echo '"Package","Version","Fixed Version","Type","CVE ID","Severity"' >"$master_report"

for report in "${WORK_DIR}/reports"/*.csv; do
	if [ "$report" != "$master_report" ] && [ -f "$report" ]; then
		# Skip header line and any "No vulnerabilities found" messages
		tail -n +2 "$report" | grep -v "No vulnerabilities found" >>"$master_report" 2>/dev/null || true
	fi
done

# Remove duplicates from master report
temp_master="${master_report}.tmp"
head -n 1 "$master_report" >"$temp_master"
tail -n +2 "$master_report" | sort -u >>"$temp_master"
mv "$temp_master" "$master_report"

total_vulns=$(($(wc -l <"$master_report") - 1))
log_info "Total unique vulnerabilities across all packages: $total_vulns"

log_info "Create tarball of all Grype reports..."
tar czf "${PROJECT_ROOT}/zarf-scan-reports.tar.gz" -C "${WORK_DIR}" reports/
log_info "Reports tarball created at ${PROJECT_ROOT}/zarf-scan-reports.tar.gz"

# summarize results
log_info ""
log_info "========== Summary =========="
successful_count=0
failed_count=0

for pkg in "${!PROCESSED_PACKAGES[@]}"; do
	if [ "${PROCESSED_PACKAGES[$pkg]}" -eq 1 ]; then
		log_info "  ✓ $pkg: Processed"
		((successful_count++))
	else
		log_warn "  ✗ $pkg: Failed/Skipped"
		((failed_count++))
	fi
done

log_info ""
log_info "Total: $successful_count successful, $failed_count failed/skipped"
log_info "Total unique vulnerabilities found: $total_vulns"
log_info "Output: ${PROJECT_ROOT}/zarf-scan-reports.tar.gz"

exit 0
