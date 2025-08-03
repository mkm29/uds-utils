#!/usr/bin/env bash

# Source common variables and functions
source "$(dirname "$(realpath "$0")")/common.sh"

# get pull creds from OnePassword
if [ -z "$UDS_USERNAME" ] || [ -z "$UDS_PASSWORD" ] || [ -z "$UDS_URL" ]; then
    warning "Using OnePassword to fetch UDS registry credentials..."
    export UDS_USERNAME=$(op read "op://Delivery-Space-Engineers/uds-registry-sld45-pull-token/username")
    export UDS_PASSWORD=$(op read "op://Delivery-Space-Engineers/uds-registry-sld45-pull-token/password")
    export UDS_URL="registry.defenseunicorns.com"
else
    info "Using existing UDS registry credentials."
fi

# Check and prompt for required environment variables if not set
if [[ -z "$UDS_USERNAME" ]]; then
    read -p "Enter UDS registry username: " UDS_USERNAME
    export UDS_USERNAME
fi

if [[ -z "$UDS_PASSWORD" ]]; then
    read -sp "Enter UDS registry password: " UDS_PASSWORD
    echo
    export UDS_PASSWORD
fi

if [[ -z "$UDS_URL" ]]; then
    read -p "Enter UDS registry URL (e.g., registry.defenseunicorns.com): " UDS_URL
    export UDS_URL
fi

if [[ -z "$ORGANIZATION" ]]; then
    read -p "Enter organization name (default: sld-45): " ORGANIZATION
    ORGANIZATION="${ORGANIZATION:-sld-45}"
    export ORGANIZATION
fi

echo "Logging into UDS registry at https://$UDS_URL with user $UDS_USERNAME"
zarf tools registry login -u "$UDS_USERNAME" -p "$UDS_PASSWORD" "$UDS_URL" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
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
    local unicorn_tag=$(echo "$tags" | grep -E '\-unicorn$' | sort -V | tail -1)
    if [ -n "$unicorn_tag" ]; then
        echo "$unicorn_tag"
        return
    fi
    
    # If no unicorn tag, find latest version-uds.X combination
    local latest_tag=$(echo "$tags" | 
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
    cmd='zarf tools registry ls "$UDS_URL/$repo"'
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
        package_name=$(echo "$repo" | sed 's|.*/||')
        package_version="$latest_tag"
        
        # Store package info as JSON object
        package_info+=("{\"name\": \"$package_name\", \"version\": \"$package_version\", \"registry\": \"$package\"}")
        
        success "Found package: $package_name:$package_version"
    else
        warning "No valid version found for $repo"
    fi
done <<< "$repositories"

# Check if any packages were loaded
if [[ ${#packages[@]} -eq 0 ]]; then
    error "No packages discovered from registry"
    exit 1
fi

success "Discovered ${#packages[@]} packages from registry"

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
    
    echo "Processing package: $package"
    # get list of images for package
    images_from_package=$(zarf --log-level warn --no-color package inspect images oci://"$package" -a amd64 | sed 's/^- //')
    if [[ $? -ne 0 ]]; then
        echo "Failed to inspect package: $package"
        continue
    fi
    
    # Store each image with its package association
    while IFS= read -r image; do
        [[ -z "$image" ]] && continue
        echo "$image" >> _images.txt
        # Store the package info JSON for this image
        image_to_package["$image"]="$package_info_json"
    done <<< "$images_from_package"
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

# iterate over _images.txt and use Grype to scan each image
count=0
while IFS= read -r image; do
    # Skip empty lines
    [[ -z "$image" ]] && continue

    count=$((count + 1))
    echo "[$count/$total_images] Scanning image: $image"

    # Replace all special characters with underscores for the filename
    safe_filename=$(echo "$image" | sed 's/[^a-zA-Z0-9-]/_/g').json

    # Capture grype output to check for auth errors
    # Redirect stdin to /dev/null to prevent grype from consuming the while loop's input
    grype_output=$(grype --platform linux/amd64 "$image" --output json --file "$safe_filename" </dev/null 2>&1)
    grype_exit_code=$?

    # Check if grype failed or if there are auth errors in the output
    if [[ $grype_exit_code -ne 0 ]] || echo "$grype_output" | grep -q "401 UNAUTHORIZED\|UNAUTHORIZED: access to the requested resource is not authorized\|pull failed\|no host address"; then
        echo "Failed to scan image: $image (exit code: $grype_exit_code)"
        echo "$image" >> errors.txt
        ((error_count++))
        # Remove the empty/invalid JSON file if created
        [[ -f "$safe_filename" ]] && rm -f "$safe_filename"
        continue
    fi

    # Verify the JSON file was created and is valid
    if [[ ! -f "$safe_filename" ]] || ! jq empty "$safe_filename" 2>/dev/null; then
        echo "Failed to create valid scan results for: $image"
        echo "$image" >> errors.txt
        ((error_count++))
        [[ -f "$safe_filename" ]] && rm -f "$safe_filename"
        continue
    fi

    echo "Scan results saved to $safe_filename"
    ((success_count++))
done < _images.txt

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
echo '[]' > all_vulnerabilities.json

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
done

# Start building the JSON structure
cat > scan-results.json <<EOF
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
    # Skip the scan-results.json file itself
    [[ "$json_file" == "scan-results.json" ]] && continue

    if [[ -f "$json_file" ]]; then
        # Add comma separator after first entry
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> scan-results.json
        fi

        # Extract vulnerability counts from this scan
        if jq empty "$json_file" 2>/dev/null; then
            # Append all vulnerabilities to our collection
            jq '.matches[]?.vulnerability.severity // "Unknown"' "$json_file" 2>/dev/null >> all_severities.txt || true

            # Collect fix states for counting fixable vulnerabilities
            jq '.matches[]? | select(.vulnerability.fix.state == "fixed") | "fixed"' "$json_file" 2>/dev/null >> all_fix_states.txt || true

            # Collect all risk values
            jq '.matches[]?.vulnerability.risk // 0' "$json_file" 2>/dev/null >> all_risks.txt || true

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
                fi
            fi
            
            # Create an enhanced result object with summary only
            echo "    {" >> scan-results.json
            echo "      \"imageName\": \"$image_name\"," >> scan-results.json
            echo "      \"scanFile\": \"$json_file\"," >> scan-results.json
            
            # Include package info if available
            if [[ -n "$package_json" ]]; then
                echo "      \"package\": $package_json," >> scan-results.json
            fi
            
            echo "      \"vulnerabilitySummary\": {" >> scan-results.json
            echo "        \"critical\": $critical," >> scan-results.json
            echo "        \"high\": $high," >> scan-results.json
            echo "        \"medium\": $medium," >> scan-results.json
            echo "        \"low\": $low," >> scan-results.json
            echo "        \"negligible\": $negligible," >> scan-results.json
            echo "        \"unknown\": $unknown," >> scan-results.json
            echo "        \"total\": $((critical + high + medium + low + negligible + unknown))," >> scan-results.json
            echo "        \"totalRisk\": $total_risk" >> scan-results.json
            echo "      }" >> scan-results.json
            echo "    }" >> scan-results.json
        fi
    fi
done

# Close the scan results array
echo "  ]" >> scan-results.json
echo "}" >> scan-results.json

# Calculate the total counts from all collected severities
if [[ -f all_severities.txt ]]; then
    # Count severities (case-insensitive)
    total_critical=$(grep -i "^\"Critical\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')
    total_high=$(grep -i "^\"High\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')
    total_medium=$(grep -i "^\"Medium\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')
    total_low=$(grep -i "^\"Low\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')
    total_negligible=$(grep -i "^\"Negligible\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')
    total_unknown=$(grep -i "^\"Unknown\"$" all_severities.txt 2>/dev/null | wc -l | tr -d ' ')

    # Clean up temporary file
    rm -f all_severities.txt
fi

# Count fixable vulnerabilities
total_fixable=0
if [[ -f all_fix_states.txt ]]; then
    total_fixable=$(wc -l < all_fix_states.txt | tr -d ' ')
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
for pkg_info in "${package_info[@]}"; do
    if [ "$first_pkg" = true ]; then
        first_pkg=false
    else
        packages_json_enhanced+=","
    fi
    
    # Extract package name from the JSON
    pkg_name=$(echo "$pkg_info" | jq -r '.name')
    
    # Get vulnerability counts for this package
    pkg_critical=${package_critical["$pkg_name"]:-0}
    pkg_high=${package_high["$pkg_name"]:-0}
    pkg_medium=${package_medium["$pkg_name"]:-0}
    pkg_low=${package_low["$pkg_name"]:-0}
    pkg_negligible=${package_negligible["$pkg_name"]:-0}
    pkg_unknown=${package_unknown["$pkg_name"]:-0}
    pkg_total=$((pkg_critical + pkg_high + pkg_medium + pkg_low + pkg_negligible + pkg_unknown))
    pkg_total_risk=${package_risk["$pkg_name"]:-0}
    
    # Create enhanced package object with vulnerability counts
    enhanced_pkg=$(echo "$pkg_info" | jq --arg critical "$pkg_critical" \
        --arg high "$pkg_high" \
        --arg medium "$pkg_medium" \
        --arg low "$pkg_low" \
        --arg negligible "$pkg_negligible" \
        --arg unknown "$pkg_unknown" \
        --arg total "$pkg_total" \
        --arg totalRisk "$pkg_total_risk" \
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
            }
        }')
    
    packages_json_enhanced+="$enhanced_pkg"
done
packages_json_enhanced+="]"

# Update the summary in the JSON file
total_vulnerabilities=$((total_critical + total_high + total_medium + total_low + total_negligible + total_unknown))
total_unfixable=$((total_vulnerabilities - total_fixable))

# Create a properly formatted packages array in a temp file
echo "$packages_json_enhanced" > packages_temp.json

# Debug: Check if packages array was created properly
debug "Enhanced packages JSON created with ${#package_info[@]} packages"

# Use jq to update the summary values and replace the packages placeholder
if jq empty scan-results.json 2>/dev/null && jq empty packages_temp.json 2>/dev/null; then
    # Read packages array and update the entire summary
    packages_array=$(cat packages_temp.json)
    
    # Update the JSON file with all summary values including packages
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
        .summary.totalRisk = $total_risk" scan-results.json > grype-results-temp.json; then
        mv grype-results-temp.json scan-results.json
        debug "Successfully updated scan-results.json with package information"
    else
        error "Failed to update scan-results.json with package information"
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

# create tarball for all json files
tarball_name="scan_results_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$tarball_name" *.json
echo "Scan results archived in $tarball_name"

# Move the output files to the artifacts directory
mv _images.txt "$artifacts_dir/images.txt"
mv "$tarball_name" "$artifacts_dir/"
cp scan-results.json "$artifacts_dir/scan-results.json"
rm -f scan-results.json

# Move errors.txt if it exists
if [[ -f errors.txt ]]; then
    mv errors.txt "$artifacts_dir/"
    echo "Error list saved to $artifacts_dir/errors.txt"
fi

echo "Image list saved to $artifacts_dir/images.txt"
echo "Combined scan results saved to $artifacts_dir/scan-results.json (includes package information)"
echo "Scan results tarball saved to $artifacts_dir/$tarball_name"

exit 0
