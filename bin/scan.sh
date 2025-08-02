#!/usr/bin/env bash

# get base directory of the script
script_dir=$(dirname "$(realpath "$0")")

# Check if packages.txt exists
packages_file="$script_dir/packages.txt"
if [[ ! -f "$packages_file" ]]; then
    echo "Error: packages.txt not found at $packages_file"
    exit 1
fi

# Read packages from packages.txt into an array
packages=()
while IFS= read -r line; do
    # Skip empty lines and lines starting with #
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    packages+=("$line")
done < "$packages_file"

# Check if any packages were loaded
if [[ ${#packages[@]} -eq 0 ]]; then
    echo "Error: No packages found in packages.txt"
    exit 1
fi

echo "Loaded ${#packages[@]} packages from packages.txt"

# make temportary directory to house packages and reports
temp_dir=$(mktemp -d)
echo "Temporary directory created at: $temp_dir"
trap 'rm -rf "$temp_dir"' EXIT
# Change to the temporary directory
cd "$temp_dir" || exit 1


for package in "${packages[@]}"; do
    echo "Processing package: $package"
    # get list of images for package
    zarf --log-level warn --no-color package inspect images oci://"$package" -a amd64 | sed 's/^- //' >> _images.txt
    if [[ $? -ne 0 ]]; then
        echo "Failed to inspect package: $package"
        continue
    fi
done

# remove duplicates from _images.txt
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

            # Create an enhanced result object
            echo "    {" >> scan-results.json
            echo "      \"imageName\": \"$image_name\"," >> scan-results.json
            echo "      \"scanFile\": \"$json_file\"," >> scan-results.json
            echo "      \"vulnerabilitySummary\": {" >> scan-results.json
            echo "        \"critical\": $critical," >> scan-results.json
            echo "        \"high\": $high," >> scan-results.json
            echo "        \"medium\": $medium," >> scan-results.json
            echo "        \"low\": $low," >> scan-results.json
            echo "        \"negligible\": $negligible," >> scan-results.json
            echo "        \"unknown\": $unknown," >> scan-results.json
            echo "        \"total\": $((critical + high + medium + low + negligible + unknown))," >> scan-results.json
            echo "        \"totalRisk\": $total_risk" >> scan-results.json
            echo "      }," >> scan-results.json
            echo "      \"scanData\":" >> scan-results.json

            # Add the original scan data
            cat "$json_file" >> scan-results.json
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

# Update the summary in the JSON file
total_vulnerabilities=$((total_critical + total_high + total_medium + total_low + total_negligible + total_unknown))
total_unfixable=$((total_vulnerabilities - total_fixable))

# Use jq to update the summary values
if jq empty scan-results.json 2>/dev/null; then
    # Create a temporary file with updated summary
    jq ".summary.vulnerabilitiesBySeverity.critical = $total_critical |
        .summary.vulnerabilitiesBySeverity.high = $total_high |
        .summary.vulnerabilitiesBySeverity.medium = $total_medium |
        .summary.vulnerabilitiesBySeverity.low = $total_low |
        .summary.vulnerabilitiesBySeverity.negligible = $total_negligible |
        .summary.vulnerabilitiesBySeverity.unknown = $total_unknown |
        .summary.totalVulnerabilities = $total_vulnerabilities |
        .summary.fixableVulnerabilities = $total_fixable |
        .summary.unfixableVulnerabilities = $total_unfixable |
        .summary.totalRisk = $total_risk" scan-results.json > grype-results-temp.json && \
    mv grype-results-temp.json scan-results.json

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

# Move the output files to the script directory
mv _images.txt "$script_dir/images.txt"
mv "$tarball_name" "$script_dir/"
jq -c . scan-results.json > "$script_dir/scan-results.json"
rm -f scan-results.json

# Move errors.txt if it exists
if [[ -f errors.txt ]]; then
    mv errors.txt "$script_dir/"
    echo "Error list saved to $script_dir/errors.txt"
fi

echo "Image list saved to $script_dir/images.txt"
echo "Combined scan results saved to $script_dir/scan-results.json"
echo "Scan results tarball saved to $script_dir/$tarball_name"

exit 0
