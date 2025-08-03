#!/usr/bin/env bash

# Source common variables and functions
# shellcheck source=./common.sh
# shellcheck disable=SC1091
source "$(dirname "$(realpath "$0")")/common.sh"

# get pull creds from OnePassword
if [ -z "$UDS_USERNAME" ] || [ -z "$UDS_PASSWORD" ]; then
	warning "Using OnePassword to fetch UDS registry credentials..."
	UDS_USERNAME=$(op read "op://Delivery-Space-Engineers/uds-registry-sld45-pull-token/username")
	export UDS_USERNAME
	UDS_PASSWORD=$(op read "op://Delivery-Space-Engineers/uds-registry-sld45-pull-token/password")
	export UDS_PASSWORD
else
	info "Using existing UDS registry credentials."
fi

# Check and prompt for required environment variables if not set
if [[ -z "$UDS_USERNAME" ]]; then
	read -rp "Enter UDS registry username: " UDS_USERNAME
	export UDS_USERNAME
fi

if [[ -z "$UDS_PASSWORD" ]]; then
	read -rsp "Enter UDS registry password: " UDS_PASSWORD
	echo
	export UDS_PASSWORD
fi

if [[ -z "$UDS_URL" ]]; then
	read -rp "Enter UDS registry URL (e.g., registry.defenseunicorns.com): " UDS_URL
	export UDS_URL
fi

if [[ -z "$ORGANIZATION" ]]; then
	read -rp "Enter organization name (default: sld-45): " ORGANIZATION
	ORGANIZATION="${ORGANIZATION:-sld-45}"
	export ORGANIZATION
fi

echo "Logging into UDS registry at https://$UDS_URL with user $UDS_USERNAME"
if ! zarf tools registry login -u "$UDS_USERNAME" -p "$UDS_PASSWORD" "$UDS_URL" >/dev/null 2>&1; then
	error "Failed to log in to UDS registry. Please check your credentials and try again."
	exit 1
fi

info "Discovering packages dynamically from registry..."
echo "Registry: $UDS_URL"
echo "Organization: $ORGANIZATION"

# Function to find the latest unicorn tag
find_latest_unicorn_tag() {
	local tags="$1"
	# First try to find unicorn tags
	local unicorn_tag
	unicorn_tag=$(echo "$tags" | grep -E '\-unicorn$' | sort -V | tail -1)
	if [ -n "$unicorn_tag" ]; then
		echo "$unicorn_tag"
		return
	fi

	# If no unicorn tag, find latest version-uds.X combination
	local latest_tag
	latest_tag=$(echo "$tags" |
		grep -E '^[0-9]+\.[0-9]+\.[0-9]+-uds\.[0-9]+' |
		sort -V | tail -1)

	# If no uds versions, try regular versions
	if [ -z "$latest_tag" ]; then
		latest_tag=$(echo "$tags" |
			grep -E '^[0-9]+\.[0-9]+\.[0-9]+' |
			sort -V | tail -1)
	fi

	# Special handling for tags starting with 'v'
	if [ -z "$latest_tag" ]; then
		latest_tag=$(echo "$tags" |
			grep -E '^v[0-9]+' |
			sort -V | tail -1)
	fi

	echo "$latest_tag"
}

# Function to check for the latest version of an image
check_latest_version() {
	local image="$1"
	local current_version=""
	local latest_version=""
	local registry_url=""
	local image_path=""

	# Parse the image to extract registry, path, and current version
	# Format: registry/path/to/image:tag or registry/path/to/image@sha256:...
	if [[ "$image" =~ ^([^/]+)/(.+):([^:]+)$ ]]; then
		registry_url="${BASH_REMATCH[1]}"
		image_path="${BASH_REMATCH[2]}"
		current_version="${BASH_REMATCH[3]}"
	elif [[ "$image" =~ ^([^/]+)/(.+)@sha256:(.+)$ ]]; then
		# SHA256 images - we can't check for newer versions
		echo "SKIP_SHA256"
		return
	else
		# Unable to parse image format
		echo "PARSE_ERROR"
		return
	fi

	# Check if we can access the registry
	debug "Checking latest version for: $registry_url/$image_path"

	# Try to list tags from the registry
	local all_tags
	if all_tags=$(zarf tools registry ls "$registry_url/$image_path" 2>/dev/null | grep -v sha256 | grep -v nightly | grep -v arm64); then
		# Successfully got tags, find the latest
		latest_version=$(echo "$all_tags" | sort -V | tail -1)

		if [ -n "$latest_version" ] && [ "$latest_version" != "$current_version" ]; then
			# Found a newer version
			echo "$latest_version"
		else
			# Current version is the latest
			echo "LATEST"
		fi
	else
		# Failed to get tags (auth error, network issue, etc.)
		echo "CHECK_FAILED"
	fi
}

# Discover packages from registry
info "Fetching repository catalog..."
catalog_response=$(curl -s -u "$UDS_USERNAME:$UDS_PASSWORD" "https://$UDS_URL/v2/_catalog")

if [[ $? -ne 0 || -z "$catalog_response" ]]; then
	error "Failed to fetch repository catalog from registry"
	exit 1
fi

# Extract repositories for the organization
repositories=$(echo "$catalog_response" | jq -r --arg org "$ORGANIZATION" '.repositories[] | select(startswith($org + "/"))')

if [[ -z "$repositories" ]]; then
	error "No repositories found for organization: $ORGANIZATION"
	exit 1
fi

# Process each repository to find latest tags
packages=()
package_info=()
packages_output=""

while read -r repo; do
	info "Processing repository: $repo"

	# Get all tags for this repository
	if ! all_tags=$(zarf tools registry ls "$UDS_URL/$repo" 2>/dev/null); then
		warning "Failed to fetch tags for repository: $repo"
		continue
	fi

	if [ -z "$all_tags" ]; then
		warning "No tags found for $repo, skipping..."
		continue
	fi

	# Find the latest tag
	latest_tag=$(find_latest_unicorn_tag "$all_tags")

	if [ -n "$latest_tag" ]; then
		package="$UDS_URL/$repo:$latest_tag"
		packages+=("$package")
		packages_output+="$package"$'\n'

		# Extract package name and version
		package_name="${repo##*/}"
		package_version="$latest_tag"

		# Store package info as JSON object
		package_info+=("{\"name\": \"$package_name\", \"version\": \"$package_version\", \"registry\": \"$package\"}")

		success "Found package: $package_name:$package_version"
	else
		warning "No valid version found for $repo"
	fi
done <<<"$repositories"

# Check if any packages were loaded
if [[ ${#packages[@]} -eq 0 ]]; then
	error "No packages discovered from registry"
	exit 1
fi

success "Discovered ${#packages[@]} packages from registry"
debug "Package info array has ${#package_info[@]} entries"

# Debug: print first package info if available
if [[ ${#package_info[@]} -gt 0 ]]; then
	debug "First package info: ${package_info[0]}"
fi

# make temportary directory to house packages and reports
temp_dir=$(mktemp -d)
echo "Temporary directory created at: $temp_dir"
trap 'rm -rf "$temp_dir"' EXIT
# Change to the temporary directory
cd "$temp_dir" || exit 1

# Create associative array to track which package each image comes from
declare -A image_to_package

for i in "${!packages[@]}"; do
	package="${packages[$i]}"
	package_info_json="${package_info[$i]}"

	# Extract package name and version from the full registry path
	package_display="${package##*/}"
	blue_no_newline "Processing package: "
	white "$package_display"
	# get list of images for package
	if ! images_from_package=$(zarf --log-level warn --no-color package inspect images oci://"$package" -a amd64 | sed 's/^- //'); then
		error "Failed to inspect package: $package"
		continue
	fi

	# Store each image with its package association
	while IFS= read -r image; do
		[[ -z "$image" ]] && continue
		echo "$image" >>_images.txt
		# Store the package info JSON for this image
		image_to_package["$image"]="$package_info_json"
	done <<<"$images_from_package"
done

# remove duplicates from _images.txt (keeping first occurrence)
sort -u _images.txt -o _images.txt

# Count total images
total_images=$(grep -c . _images.txt || echo "0")
echo "Total images to scan: $total_images"

# Initialize error tracking
error_count=0
success_count=0

# Record start time for scan duration
scan_start_time=$(date +%s)

# Create associative array to store latest version info for each image
declare -A image_latest_versions

# iterate over _images.txt and use Grype to scan each image
count=0
while IFS= read -r image; do
	# Skip empty lines
	[[ -z "$image" ]] && continue

	count=$((count + 1))
	blue_no_newline "[$count/$total_images] "
	white_no_newline "Scanning image: "
	green "$image"

	# Check for latest version of the image
	echo "  Checking for latest version..."
	latest_version_result=$(check_latest_version "$image")
	image_latest_versions["$image"]="$latest_version_result"

	case "$latest_version_result" in
	"LATEST")
		success "  ✓ Image is already at the latest version"
		;;
	"SKIP_SHA256")
		echo "  - Skipping version check (SHA256 digest)"
		;;
	"PARSE_ERROR")
		warning "  ⚠ Unable to parse image format"
		;;
	"CHECK_FAILED")
		error "  ⚠ Failed to check for latest version"
		;;
	*)
		yellow_no_newline "  ⚠ Newer version available: "
		yellow "$latest_version_result"
		;;
	esac

	# Replace all special characters with underscores for the filename
	safe_filename="${image//[^a-zA-Z0-9-]/_}.json"

	# Capture grype output to check for auth errors
	# Redirect stdin to /dev/null to prevent grype from consuming the while loop's input
	grype_output=$(grype --platform linux/amd64 "$image" --output json --file "$safe_filename" </dev/null 2>&1)
	grype_exit_code=$?

	# Check if grype failed or if there are auth errors in the output
	if [[ $grype_exit_code -ne 0 ]] || echo "$grype_output" | grep -q "401 UNAUTHORIZED\|UNAUTHORIZED: access to the requested resource is not authorized\|pull failed\|no host address"; then
		error "Failed to scan image: $image (exit code: $grype_exit_code)"
		echo "$image" >>errors.txt
		((error_count++))
		# Remove the empty/invalid JSON file if created
		[[ -f "$safe_filename" ]] && rm -f "$safe_filename"
		continue
	fi

	# Verify the JSON file was created and is valid
	if [[ ! -f "$safe_filename" ]] || ! jq empty "$safe_filename" 2>/dev/null; then
		error "Failed to create valid scan results for: $image"
		echo "$image" >>errors.txt
		((error_count++))
		[[ -f "$safe_filename" ]] && rm -f "$safe_filename"
		continue
	fi

	echo "Scan results saved to $safe_filename"
	((success_count++))
done <_images.txt

echo "Completed scanning $count images: $success_count successful, $error_count errors"

# If errors.txt exists, note it
if [[ -f errors.txt ]]; then
	echo "Images with authentication errors saved to errors.txt"
fi

# Combine all individual JSON results into a single scan-results.json
echo "Combining scan results into scan-results.json..."

# Get current timestamp and calculate scan duration
scan_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
scan_end_time=$(date +%s)
scan_duration=$((scan_end_time - scan_start_time))

# Create a temporary file to collect all vulnerabilities
echo '[]' >all_vulnerabilities.json

# Initialize counters for vulnerability summary
total_critical=0
total_high=0
total_medium=0
total_low=0
total_negligible=0
total_unknown=0
total_vulnerabilities=0

# Create associative arrays to track vulnerabilities by package
declare -A package_critical
declare -A package_high
declare -A package_medium
declare -A package_low
declare -A package_negligible
declare -A package_unknown
declare -A package_risk
declare -A package_outdated_images

# Initialize package vulnerability counters
for pkg_info in "${package_info[@]}"; do
	pkg_name=$(echo "$pkg_info" | jq -r '.name')
	package_critical["$pkg_name"]=0
	package_high["$pkg_name"]=0
	package_medium["$pkg_name"]=0
	package_low["$pkg_name"]=0
	package_negligible["$pkg_name"]=0
	package_unknown["$pkg_name"]=0
	package_risk["$pkg_name"]=0
	package_outdated_images["$pkg_name"]=""
done

# Start building the JSON structure
cat >scan-results.json <<EOF
{
  "metadata": {
    "scanTimestamp": "$scan_timestamp",
    "scanDurationSeconds": $scan_duration,
    "scanDuration": "${scan_duration}s",
    "totalImagesScanned": $count,
    "successfulScans": $success_count,
    "failedScans": $error_count,
    "grypeVersion": "$(grype --version 2>/dev/null | cut -d' ' -f2 || echo 'unknown')"
  },
  "summary": {
    "packages": [],
    "totalPackages": ${#packages[@]},
    "vulnerabilitiesBySeverity": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "negligible": 0,
      "unknown": 0
    },
    "totalVulnerabilities": 0,
    "fixableVulnerabilities": 0,
    "unfixableVulnerabilities": 0,
    "totalRisk": 0
  },
  "results": [
EOF

# Process each JSON file and extract vulnerability counts
first=true
for json_file in *.json; do
	# Skip the scan-results.json file itself and temporary files
	[[ "$json_file" == "scan-results.json" ]] && continue
	[[ "$json_file" == "all_vulnerabilities.json" ]] && continue

	if [[ -f "$json_file" ]]; then
		# Add comma separator after first entry
		if [[ "$first" == "true" ]]; then
			first=false
		else
			echo "," >>scan-results.json
		fi

		# Extract vulnerability counts from this scan
		if jq empty "$json_file" 2>/dev/null; then
			# Append all vulnerabilities to our collection
			jq '.matches[]?.vulnerability.severity // "Unknown"' "$json_file" 2>/dev/null >>all_severities.txt || true

			# Collect fix states for counting fixable vulnerabilities
			jq '.matches[]? | select(.vulnerability.fix.state == "fixed") | "fixed"' "$json_file" 2>/dev/null >>all_fix_states.txt || true

			# Collect all risk values
			jq '.matches[]?.vulnerability.risk // 0' "$json_file" 2>/dev/null >>all_risks.txt || true

			# Count vulnerabilities by severity for this specific image
			critical=$(jq '[.matches[]? | select(.vulnerability.severity | ascii_downcase == "critical")] | length' "$json_file" 2>/dev/null || echo 0)
			high=$(jq '[.matches[]? | select(.vulnerability.severity | ascii_downcase == "high")] | length' "$json_file" 2>/dev/null || echo 0)
			medium=$(jq '[.matches[]? | select(.vulnerability.severity | ascii_downcase == "medium")] | length' "$json_file" 2>/dev/null || echo 0)
			low=$(jq '[.matches[]? | select(.vulnerability.severity | ascii_downcase == "low")] | length' "$json_file" 2>/dev/null || echo 0)
			negligible=$(jq '[.matches[]? | select(.vulnerability.severity | ascii_downcase == "negligible")] | length' "$json_file" 2>/dev/null || echo 0)
			unknown=$(jq '[.matches[]? | select(.vulnerability.severity == "Unknown" or .vulnerability.severity == null or .vulnerability.severity | ascii_downcase == "unknown")] | length' "$json_file" 2>/dev/null || echo 0)

			# Calculate total risk for this image
			total_risk=$(jq '[.matches[]?.vulnerability.risk // 0] | add' "$json_file" 2>/dev/null || echo 0)

			# Get image name from the scan
			image_name=$(jq -r '.source.target.userInput // "unknown"' "$json_file" 2>/dev/null || echo "unknown")

			# Get package info for this image
			package_json="${image_to_package[$image_name]}"

			# Get latest version info for this image
			latest_version_info="${image_latest_versions[$image_name]}"

			# If we have package info, update package vulnerability counts
			if [[ -n "$package_json" ]]; then
				pkg_name=$(echo "$package_json" | jq -r '.name')
				if [[ -n "$pkg_name" && "$pkg_name" != "null" ]]; then
					((package_critical["$pkg_name"] += critical))
					((package_high["$pkg_name"] += high))
					((package_medium["$pkg_name"] += medium))
					((package_low["$pkg_name"] += low))
					((package_negligible["$pkg_name"] += negligible))
					((package_unknown["$pkg_name"] += unknown))
					# Use bc for floating point addition
					package_risk["$pkg_name"]=$(echo "${package_risk["$pkg_name"]} + $total_risk" | bc)

					# Track outdated images
					if [[ "$latest_version_info" != "LATEST" && "$latest_version_info" != "SKIP_SHA256" &&
						"$latest_version_info" != "PARSE_ERROR" && "$latest_version_info" != "CHECK_FAILED" ]]; then
						# This is an outdated image
						current_version=$(echo "$image_name" | grep -oE ':[^:]+$' | sed 's/^://')
						outdated_entry="{\"image\": \"$image_name\", \"currentVersion\": \"$current_version\", \"latestVersion\": \"$latest_version_info\"}"

						# Append to the package's outdated images list
						if [[ -z "${package_outdated_images[$pkg_name]}" ]]; then
							package_outdated_images["$pkg_name"]="$outdated_entry"
						else
							package_outdated_images["$pkg_name"]="${package_outdated_images[$pkg_name]},DELIMITER,$outdated_entry"
						fi
					fi
				fi
			fi

			# Create an enhanced result object with summary only
			{
				echo "    {"
				echo "      \"imageName\": \"$image_name\","
				echo "      \"scanFile\": \"$json_file\","

				# Include package info if available
				if [[ -n "$package_json" ]]; then
					echo "      \"package\": $package_json,"
				fi

				# Include version check info
				echo "      \"versionCheck\": {"
				case "$latest_version_info" in
				"LATEST")
					echo "        \"status\": \"up-to-date\","
					echo "        \"message\": \"Image is at the latest version\""
					;;
				"SKIP_SHA256")
					echo "        \"status\": \"skipped\","
					echo "        \"message\": \"Version check skipped for SHA256 digest\""
					;;
				"PARSE_ERROR")
					echo "        \"status\": \"error\","
					echo "        \"message\": \"Unable to parse image format\""
					;;
				"CHECK_FAILED")
					echo "        \"status\": \"failed\","
					echo "        \"message\": \"Failed to check for latest version\""
					;;
				*)
					echo "        \"status\": \"outdated\","
					echo "        \"currentVersion\": \"$(echo "$image_name" | grep -oE ':[^:]+$' | sed 's/^://')\","
					echo "        \"latestVersion\": \"$latest_version_info\","
					echo "        \"message\": \"Newer version available\""
					;;
				esac
				echo "      },"

				echo "      \"vulnerabilitySummary\": {"
				echo "        \"critical\": $critical,"
				echo "        \"high\": $high,"
				echo "        \"medium\": $medium,"
				echo "        \"low\": $low,"
				echo "        \"negligible\": $negligible,"
				echo "        \"unknown\": $unknown,"
				echo "        \"total\": $((critical + high + medium + low + negligible + unknown)),"
				echo "        \"totalRisk\": $total_risk"
				echo "      }"
				echo "    }"
			} >>scan-results.json
		fi
	fi
done

# Close the scan results array
echo "  ]" >>scan-results.json
echo "}" >>scan-results.json

# Calculate the total counts from all collected severities
if [[ -f all_severities.txt ]]; then
	# Count severities (case-insensitive)
	total_critical=$(grep -ic "^\"Critical\"$" all_severities.txt 2>/dev/null || echo 0)
	total_high=$(grep -ic "^\"High\"$" all_severities.txt 2>/dev/null || echo 0)
	total_medium=$(grep -ic "^\"Medium\"$" all_severities.txt 2>/dev/null || echo 0)
	total_low=$(grep -ic "^\"Low\"$" all_severities.txt 2>/dev/null || echo 0)
	total_negligible=$(grep -ic "^\"Negligible\"$" all_severities.txt 2>/dev/null || echo 0)
	total_unknown=$(grep -ic "^\"Unknown\"$" all_severities.txt 2>/dev/null || echo 0)

	# Clean up temporary file
	rm -f all_severities.txt
fi

# Count fixable vulnerabilities
total_fixable=0
if [[ -f all_fix_states.txt ]]; then
	total_fixable=$(wc -l <all_fix_states.txt | tr -d ' ')
	rm -f all_fix_states.txt
fi

# Calculate total risk across all images
total_risk=0
if [[ -f all_risks.txt ]]; then
	# Use jq to sum all risk values
	total_risk=$(jq -s 'add' all_risks.txt 2>/dev/null || echo 0)
	rm -f all_risks.txt
fi

# Create enhanced packages JSON with vulnerability counts
packages_json_enhanced="["
first_pkg=true
debug "Starting to process ${#package_info[@]} packages for enhanced JSON"
for pkg_info in "${package_info[@]}"; do
	if [ "$first_pkg" = true ]; then
		first_pkg=false
	else
		packages_json_enhanced+=","
	fi

	# Extract package name from the JSON
	pkg_name=$(echo "$pkg_info" | jq -r '.name')
	debug "Processing package: $pkg_name"

	# Get vulnerability counts for this package
	pkg_critical=${package_critical["$pkg_name"]:-0}
	pkg_high=${package_high["$pkg_name"]:-0}
	pkg_medium=${package_medium["$pkg_name"]:-0}
	pkg_low=${package_low["$pkg_name"]:-0}
	pkg_negligible=${package_negligible["$pkg_name"]:-0}
	pkg_unknown=${package_unknown["$pkg_name"]:-0}
	pkg_total=$((pkg_critical + pkg_high + pkg_medium + pkg_low + pkg_negligible + pkg_unknown))
	pkg_total_risk=${package_risk["$pkg_name"]:-0}

	# Get outdated images for this package
	pkg_outdated="${package_outdated_images[$pkg_name]:-}"

	# Convert the delimited string to a JSON array
	outdated_json_array="[]"
	if [[ -n "$pkg_outdated" ]]; then
		# Build JSON array properly without IFS manipulation
		outdated_json_array="["
		first_item=true
		while [[ -n "$pkg_outdated" ]]; do
			# Find the delimiter position
			if [[ "$pkg_outdated" =~ ^(.*),DELIMITER,(.*)$ ]]; then
				item="${BASH_REMATCH[1]}"
				remaining="${BASH_REMATCH[2]}"
			else
				# Last item (no delimiter)
				item="$pkg_outdated"
				remaining=""
			fi

			if [ "$first_item" = true ]; then
				first_item=false
			else
				outdated_json_array+=","
			fi
			outdated_json_array+="$item"

			# Move to the next item
			pkg_outdated="$remaining"
			[[ -z "$pkg_outdated" ]] && break
		done
		outdated_json_array+="]"
	fi

	# Debug the JSON array
	debug "Package $pkg_name outdated_json_array: $outdated_json_array"

	# Create enhanced package object with vulnerability counts and outdated images
	# First validate the JSON array
	if ! echo "$outdated_json_array" | jq . >/dev/null 2>&1; then
		error "Invalid JSON array for package $pkg_name, using empty array"
		outdated_json_array="[]"
	fi

	if enhanced_pkg=$(echo "$pkg_info" | jq --arg critical "$pkg_critical" \
		--arg high "$pkg_high" \
		--arg medium "$pkg_medium" \
		--arg low "$pkg_low" \
		--arg negligible "$pkg_negligible" \
		--arg unknown "$pkg_unknown" \
		--arg total "$pkg_total" \
		--arg totalRisk "$pkg_total_risk" \
		--argjson outdatedImages "$outdated_json_array" \
		'. + {
            "vulnerabilitySummary": {
                "critical": ($critical | tonumber),
                "high": ($high | tonumber),
                "medium": ($medium | tonumber),
                "low": ($low | tonumber),
                "negligible": ($negligible | tonumber),
                "unknown": ($unknown | tonumber),
                "total": ($total | tonumber),
                "totalRisk": ($totalRisk | tonumber)
            },
            "outdatedImages": $outdatedImages
        }' 2>&1); then
		debug "Enhanced package JSON for $pkg_name created successfully"
	else
		error "Failed to create enhanced package JSON for $pkg_name"
		# Use basic package info without enhancements
		enhanced_pkg="$pkg_info"
	fi

	packages_json_enhanced+="$enhanced_pkg"
done
packages_json_enhanced+="]"

debug "Final packages_json_enhanced length: ${#packages_json_enhanced}"

# Update the summary in the JSON file
total_vulnerabilities=$((total_critical + total_high + total_medium + total_low + total_negligible + total_unknown))
total_unfixable=$((total_vulnerabilities - total_fixable))

# Create a properly formatted packages array in a temp file
echo "$packages_json_enhanced" >packages_temp.json

# Debug: Check if packages array was created properly
debug "Enhanced packages JSON created with ${#package_info[@]} packages"
debug "packages_temp.json size: $(wc -c <packages_temp.json) bytes"
if [ -s packages_temp.json ]; then
	debug "First 200 chars of packages_temp.json: $(head -c 200 packages_temp.json)"
else
	error "packages_temp.json is empty!"
fi

# Use jq to update the summary values and replace the packages placeholder
if jq empty scan-results.json 2>/dev/null && jq empty packages_temp.json 2>/dev/null; then
	# Read packages array and update the entire summary
	packages_array=$(cat packages_temp.json)

	# Update the JSON file with all summary values including packages
	debug "Updating scan-results.json with packages array"
	if jq --argjson packages "$packages_array" \
		".summary.packages = \$packages |
        .summary.vulnerabilitiesBySeverity.critical = $total_critical |
        .summary.vulnerabilitiesBySeverity.high = $total_high |
        .summary.vulnerabilitiesBySeverity.medium = $total_medium |
        .summary.vulnerabilitiesBySeverity.low = $total_low |
        .summary.vulnerabilitiesBySeverity.negligible = $total_negligible |
        .summary.vulnerabilitiesBySeverity.unknown = $total_unknown |
        .summary.totalVulnerabilities = $total_vulnerabilities |
        .summary.fixableVulnerabilities = $total_fixable |
        .summary.unfixableVulnerabilities = $total_unfixable |
        .summary.totalRisk = $total_risk" scan-results.json >grype-results-temp.json; then
		mv grype-results-temp.json scan-results.json
		debug "Successfully updated scan-results.json with package information"
	else
		error "Failed to update scan-results.json with package information"
		debug "jq command failed - checking packages_array content"
		debug "packages_array length: ${#packages_array}"
	fi

	# Clean up temp file
	rm -f packages_temp.json

	echo "Successfully created scan-results.json with $success_count scan results"
	echo "Total vulnerabilities found: $total_vulnerabilities (Critical: $total_critical, High: $total_high, Medium: $total_medium, Low: $total_low)"
	echo "Fixable vulnerabilities: $total_fixable | Unfixable vulnerabilities: $total_unfixable"
	echo "Total cumulative risk score: $total_risk"
else
	echo "Warning: scan-results.json may be malformed"
fi

# Clean up the temporary vulnerability collection file
rm -f all_vulnerabilities.json

# create tarball for all json files (excluding temporary files)
tarball_name="scan_results_$(date +%Y%m%d_%H%M%S).tar.gz"
# Use find to exclude temporary files
find . -maxdepth 1 -name "*.json" ! -name "all_vulnerabilities.json" ! -name "scan-results.json" -exec tar -czf "$tarball_name" {} +
echo "Scan results archived in $tarball_name"

# Move the output files to the artifacts directory
# shellcheck disable=SC2154  # artifacts_dir is defined in common.sh
mv _images.txt "${artifacts_dir}/images.txt"
mv "$tarball_name" "${artifacts_dir}/"
cp scan-results.json "${artifacts_dir}/scan-results.json"
rm -f scan-results.json

# Move errors.txt if it exists
if [[ -f errors.txt ]]; then
	mv errors.txt "${artifacts_dir}/"
	echo "Error list saved to ${artifacts_dir}/errors.txt"
fi

echo "Image list saved to ${artifacts_dir:-artifacts}/images.txt"
echo "Combined scan results saved to ${artifacts_dir:-artifacts}/scan-results.json (includes package information)"
echo "Scan results tarball saved to ${artifacts_dir:-artifacts}/$tarball_name"

exit 0
