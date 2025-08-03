#!/usr/bin/env bash

set -euo pipefail

# Source common variables and functions
# shellcheck source=./common.sh
# shellcheck disable=SC1091
source "$(dirname "$(realpath "$0")")/common.sh"

# This script scans all Kubernetes namespaces using Trivy and generates a KBOM (Kubernetes Bill of Materials).
# Blog post: https://www.aquasec.com/blog/introducing-kbom-kubernetes-bill-of-materials/
#
# Requirements:
# - Trivy installed and configured
# - Access to a Kubernetes cluster with kubectl configured
# - yq installed for parsing YAML files
# - jq installed for JSON processing (if needed)
# - Ensure that the Zarf Docker registry is running in the 'zarf' namespace
# - Ensure that the kubeconfig file is accessible and valid
# - Ensure that the Zarf Docker registry service and port are correctly specified
#
# Author: Mitchell Murphy<mitchell.murphy@defenseunicorns.com>
# License: Apache-2.0
# Version: 0.1.0
# Date: 2025-07-09

# Globals for cleanup
port_forward_pid=""
cleaned_up=false

# Cleanup function to run on exit
cleanup() {
	if [ "$cleaned_up" = true ]; then
		return
	fi

	if [[ -n "$port_forward_pid" ]] && kill -0 "$port_forward_pid" 2>/dev/null; then
		info "Cleaning up port-forwarding process (PID: $port_forward_pid)..."
		kill "$port_forward_pid" 2>/dev/null || error "Failed to kill port-forwarding process. Please check manually."
	fi

	unset KUBECONFIG
	unset NO_COLOR
	cleaned_up=true
}

# Run cleanup on exit, Ctrl+C, or termination
trap cleanup EXIT INT TERM

info "🦄 Starting Trivy scan of all Kubernetes namespaces 🦄"
echo

# prompt user for path of kubeconfig file
read -r -p "Enter the path to your kubeconfig file (must be absolute path): " kubeconfig_path
if [ -z "$kubeconfig_path" ]; then
	error "Kubeconfig path cannot be empty. Please provide a valid path."
	exit 1
fi

# prompt user to enter kube context name
read -r -p "Enter the Kubernetes context name (default: uds-eks-test-uds-context): " kube_context
if [ -z "$kube_context" ]; then
	kube_context="uds-eks-test-uds-context"
fi

# prompt user to enter svc name for zarf registry
read -r -p "Enter the service name for Zarf Docker registry (default: zarf-docker-registry): " zarf_registry_svc
if [ -z "$zarf_registry_svc" ]; then
	zarf_registry_svc="zarf-docker-registry"
fi

# prompt user to enter port for zarf registry
read -r -p "Enter the port for Zarf Docker registry (default: 31999): " zarf_registry_port
if [ -z "$zarf_registry_port" ]; then
	zarf_registry_port="31999"
fi

# use yq to extract the cluster name from the kubeconfig file
if ! cluster_name=$(yq '.clusters[0].name' "$kubeconfig_path" 2>/dev/null); then
	error "Failed to extract cluster name from kubeconfig file. Please ensure yq is installed and the kubeconfig file is valid. Setting default cluster name to 'uds-default-cluster'."
	cluster_name="uds-default-cluster"
fi

# prompt user to enter namespaces to scan
read -r -p "Enter the namespaces to scan (comma-separated, default: all namespaces): " namespaces_input
if [ -z "$namespaces_input" ]; then
	namespaces_input="all"
fi

# prompt user to enter the filename to save the output
read -r -p "Enter the output filename (default: ${cluster_name}-kbom.txt): " output_filename
if [ -z "$output_filename" ]; then
	output_filename="${cluster_name}-kbom.txt"
fi
# Save to artifacts directory
# shellcheck disable=SC2154  # artifacts_dir is defined in common.sh
output_filepath="${artifacts_dir}/${output_filename}"

# prompt user to enter the vulnerability severity levels to include
read -r -p "Enter the vulnerability severity levels to include (comma-separated, default: CRITICAL,HIGH): " severity_levels
if [ -z "$severity_levels" ]; then
	severity_levels="CRITICAL,HIGH"
fi

# prompt the user to confirm settings
echo
info "You have entered the following settings:"
echo
echo -e "\tKubeconfig Path: $kubeconfig_path"
echo -e "\tKubernetes Context: $kube_context"
echo -e "\tZarf Docker Registry Service: $zarf_registry_svc"
echo -e "\tZarf Docker Registry Port: $zarf_registry_port"
echo -e "\tOutput File: $output_filepath"
echo -e "\tVulnerability Severity Levels: $severity_levels"
echo
read -r -p "Is this correct? (y/n): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
	error "Exiting script. Please run again with correct settings."
	exit 1
fi
echo

export KUBECONFIG="$kubeconfig_path"

# ensure that the kubernetes cluster (from outopt of `kubectl config current-context`) is "uds-eks-test-uds-context" and if not switch to it
current_context=$(kubectl config current-context)
if [ "$current_context" != "${kube_context}" ]; then
	info "Switching to the '${kube_context}' Kubernetes context..."
	if ! kubectl config use-context "${kube_context}" 2>/dev/null; then
		error "Failed to switch to the '${kube_context}'. Please check your Kubernetes configuration."
		exit 1
	fi
else
	info "Already using the '${kube_context}' Kubernetes context."
fi
echo
export NO_COLOR=1

# you will need to port-forward to the zarf docker registry
# run this command in the background, but capture the PID so you can kill it later
info "Port-forwarding to the Zarf Docker registry..."
kubectl port-forward -n zarf "svc/${zarf_registry_svc}" "${zarf_registry_port}":5000 >/dev/null 2>&1 &
port_forward_pid=$!
sleep 2

# ensure that the port-forwarding is successful
if ! nc -z localhost "${zarf_registry_port}"; then
	error "Failed to port-forward to the Zarf Docker registry. Please ensure the Zarf Docker registry is running in the 'zarf' namespace."
	kill $port_forward_pid
	exit 1
fi

# if namespace_input equals all, retrieve the list of Kubernetes namespaces and converts them into a space-separated string.
if [ "$namespaces_input" == "all" ]; then
	namespaces=$(kubectl get ns -o name | cut -d/ -f2 | tr '\n' ' ')
else
	namespaces="$namespaces_input"
fi

# If no namespaces are found, exit
if [ -z "$namespaces" ]; then
	error "No namespaces found."
	exit 0
fi

echo
num_namespaces=$(echo "$namespaces" | wc -w)
info "Number of namespaces to scan: $num_namespaces"
echo

info "Starting Trivy scan..."
echo
start_time=$(date +%s)
if ! trivy kubernetes --report summary --insecure --output "${output_filepath}" \
	--format table --disable-node-collector \
	--include-namespaces "${namespaces// /,}" \
	--ignore-unfixed --severity "${severity_levels}" \
	--timeout 10m0s \
	--kubeconfig "${kubeconfig_path}" \
	--skip-images; then
	error "Trivy scan failed."
	exit 1
else
	end_time=$(date +%s)
fi

echo
info "Trivy scan completed successfully."
info "Total time taken: $((end_time - start_time)) seconds"
info "Output saved to: $output_filepath"
echo
