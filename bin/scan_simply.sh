#!/usr/bin/env bash

set -euo pipefail

REGISTRY=registry.defenseunicorns.com
ORG=sld-45
REPO=gitlab-runner
#init
ARCH=amd64
FLAVOR="registry1"
VERSION=18.2.0-uds.1
#v0.61.0

# check that prereqs are installed
if ! command -v oras &> /dev/null; then
    echo "oras could not be found, please install oras to proceed."
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "jq could not be found, please install jq to proceed."
    exit 1
fi
if ! command -v grype &> /dev/null; then
    echo "grype could not be found, please install grype to proceed."
    exit 1
fi
echo "All prerequisites found."

mkdir -p ./packages ./reports ./extracted

echo "Pull gitlab-runner ${VERSION}..."
if [ -n "$FLAVOR" ]; then
    FLAVOR="-$FLAVOR"
fi
zarf package pull "oci://${REGISTRY}/${ORG}/${REPO}:${VERSION}${FLAVOR}" -a ${ARCH}

echo "Unpack gitlab-runner package..."
if [ "${REPO}" != "init" ]; then
    REPO="package-${REPO}"
fi
tar xzf zarf-${REPO}-${ARCH}-${VERSION}${FLAVOR}.tar.zst -C ./packages

echo "Getting digests from OCI artifact..."
src_dir="./packages/images"
digests=$(jq -r '.manifests[].digest' "${src_dir}/index.json")

for digest in $digests; do
    image_name=$(jq -r --arg d "$digest" '.manifests[] | select(.digest==$d) | .annotations."org.opencontainers.image.ref.name"' "${src_dir}/index.json" | sed 's|.*/||' | sed 's|:|_|g')

    dir_name="extracted/${image_name}"
    mkdir -p "$dir_name"

    echo "Extracting $image_name to $dir_name"
    oras copy --from-oci-layout --to-oci-layout "${src_dir}@${digest}" "${dir_name}:latest" &> /dev/null
done

# go through each extracted image and scan it with grype
for dir in ./extracted/*; do
    if [ -d "$dir" ]; then
        image_name=$(basename "$dir")
        echo "Scanning $image_name for vulnerabilities..."
        grype oci-dir:"$dir" -o json --file "./reports/${image_name}.json" &> /dev/null
        echo "Vulnerability report saved to ./reports/${image_name}.json"
    fi
done

echo "All scans completed. Reports are in the ./reports directory."
echo "Computing summary statistics..."
jq -s '
  map(.matches[]) | 
  group_by(.vulnerability.severity) | 
  map({severity: .[0].vulnerability.severity, count: length})
' ./reports/*.json

# remove "package" from REPO
REPO2=${REPO}
if [[ $REPO == package-* ]]; then
    REPO2=${REPO#package-}
fi
echo "Archiving reports..."
tar -czf "${REPO2}-vuln-reports-${VERSION}.tar.gz" -C ./reports .
echo "Reports archived to ${REPO}-vuln-reports-${VERSION}.tar.gz"

echo "Cleaning up..."
rm -rf ./packages ./extracted ./reports "zarf-${REPO}-${ARCH}-${VERSION}${FLAVOR}.tar.zst"