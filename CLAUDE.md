# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

uds-utils is a collection of utility scripts for interacting with UDS (Unicorn Delivery Service) systems. The repository contains standalone Bash scripts for AWS SSM tunneling and container image vulnerability scanning.

## Repository Structure

- `bin/` - Utility scripts
  - `uds-ssm` - AWS SSM port forwarding utility for EKS cluster access
  - `scan.sh` - Container image vulnerability scanning script using Grype
- `packages.txt` - List of OCI packages to scan
- `images.txt` - Generated list of container images from scan

## Development Commands

### Testing uds-ssm

```bash
# Make script executable
chmod +x bin/uds-ssm

# Test script locally (requires AWS CLI and session-manager-plugin)
./bin/uds-ssm help
./bin/uds-ssm status
```

### Testing scan.sh

```bash
# Make script executable
chmod +x bin/scan.sh

# Run scan (requires zarf and grype installed)
./bin/scan.sh
```

## Key Technical Details

### uds-ssm Script

- **Purpose**: Establishes secure tunnels to EC2 instances for kubectl access to EKS clusters
- **Key Features**:
  - Port forwarding (EKS API on localhost:8443)
  - Interactive SSH sessions
  - Session management with persistent state
  - Kubeconfig generation and management
- **State Directory**: `~/.local/state/udsm/`
- **Default Values**:
  - Cluster: `uds-eks-dev-uds`
  - Region: `us-gov-east-1`
  - Profile: `jam-dev`
  - Filter: `*bastion*`

### scan.sh Script

- **Purpose**: Scans container images for vulnerabilities using Grype
- **Workflow**:
  1. Reads OCI packages from `packages.txt` in repository root
  1. Extracts images using `zarf package inspect`
  1. Scans each image with Grype
  1. Aggregates results into `scan-results.json`
  1. Creates tarball archive of all scan results
- **Output Files** (written to repository root):
  - `images.txt` - List of all unique images
  - `scan-results.json` - Combined vulnerability report
  - `errors.txt` - Images that failed to scan
  - Timestamped tarball of all JSON results

## Important Considerations

1. **AWS Permissions**: uds-ssm requires AWS CLI configured with permissions for EC2, EKS, and SSM operations
1. **External Dependencies**:
   - uds-ssm: `aws`, `session-manager-plugin`, `kubectl`
   - scan.sh: `zarf`, `grype`, `jq`
1. **Error Handling**: Both scripts include comprehensive error handling and cleanup mechanisms
1. **Session Management**: uds-ssm maintains persistent session state across invocations
