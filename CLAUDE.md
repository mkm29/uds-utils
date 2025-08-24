# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

UDS Utils is a collection of Bash utility scripts for interacting with UDS (Unicorn Delivery Service) systems. The repository provides tools for secure AWS SSM tunneling to EKS clusters, vulnerability scanning of container images, SSL certificate generation, and Kubernetes security auditing.

## Essential Commands

### Script Execution

All executable scripts are located in the `bin/` directory:

```bash
# Make scripts executable after cloning
chmod +x bin/uds-ssm bin/scan.sh bin/letscerts.sh bin/generate-kbom.sh

# Add to PATH for global access
export PATH="$PATH:$(pwd)/bin"
```

### UDS SSM Tunnel Management

```bash
# Start port forwarding session to EKS cluster
uds-ssm start

# Start with custom parameters
uds-ssm start --cluster-name my-cluster --region us-west-2

# Configure kubeconfig and merge with existing
uds-ssm start --kubeconfig --merge

# Interactive SSH session
uds-ssm ssh

# Check active session status
uds-ssm status

# Stop sessions
uds-ssm stop --session-id <id>
uds-ssm stop --all
```

### Vulnerability Scanning

```bash
# Basic vulnerability scan of UDS packages
./bin/scan.sh

# Debug mode with verbose output
./bin/scan.sh --debug

# Custom output directory and architecture
./bin/scan.sh --output /path/to/results --arch arm64
```

### Code Quality

```bash
# Validate all shell scripts
shellcheck bin/*

# Check for common issues
shellcheck -x bin/scan.sh bin/uds-ssm
```

## Architecture and Key Components

### Script Organization

```
bin/
├── common.sh           # Shared utilities and color functions
├── detect_platform.sh  # OS and architecture detection
├── uds-ssm            # AWS SSM tunnel management
├── scan.sh            # Container vulnerability scanning
├── letscerts.sh       # Let's Encrypt certificate generation
└── generate-kbom.sh   # Kubernetes security auditing
```

### Common Infrastructure (`bin/common.sh`)

The repository uses a centralized common library providing:

- **Color-coded Output**: Consistent `info()`, `error()`, `warning()`, `success()`, `debug()` functions
- **Platform Detection**: OS and architecture abstraction via `detect_platform.sh`
- **Path Management**: Automatic project root and artifacts directory setup
- **OCI Image Processing**: Functions for extracting images from Zarf packages
- **Registry Integration**: Login utilities for UDS and Iron Bank registries

### Core Architecture Patterns

#### State Management

- **uds-ssm**: Uses `~/.local/state/udsm/` for persistent session tracking
- **scan.sh**: Creates `artifacts/` directory for scan results and temporary files

#### Credential Management

Scripts support multiple credential sources in order of preference:

1. Environment variables (`UDS_USERNAME`, `UDS_PASSWORD`, etc.)
1. Interactive prompts as fallback

#### Error Handling

- Consistent error tracking and reporting across all scripts
- JSON-formatted error logs in scan results
- Proper cleanup functions with trap handling

### Package Discovery and Version Management

The scanning system includes sophisticated package discovery:

- **Registry API Integration**: Discovers packages dynamically from UDS registries
- **Version Filtering**: Intelligent filtering of architecture-specific and development tags
- **Unicorn Tag Priority**: Prefers `-unicorn` suffixed versions when available
- **FIPS Compatibility**: Separate version tracking for FIPS-certified images

### Security Scanning Pipeline (`scan.sh`)

1. **Package Discovery**: Query registry APIs to find available UDS packages
1. **Package Pulling**: Use `zarf package pull` to download OCI archives
1. **Image Extraction**: Extract embedded container images from package archives
1. **Direct Scanning**: Scan extracted OCI directories with Grype (no registry push/pull)
1. **Version Analysis**: Compare current versions against latest available tags
1. **Report Generation**: JSON-formatted vulnerability reports with package attribution

## Configuration Files

### versions.json Structure

Contains package and registry configuration:

```json
{
  "packages": [
    {
      "name": "package-name",
      "version": "1.2.3-uds.0-unicorn",
      "environments": ["marvin", "rad"]
    }
  ],
  "registries": [
    {
      "name": "registry1",
      "url": "registry1.dso.mil",
      "hasCredentials": true
    }
  ]
}
```

### Default Configuration Values

Key defaults that can be modified in scripts:

**uds-ssm**:

- `DEFAULT_CLUSTER_NAME="uds-eks-dev-uds"`
- `DEFAULT_REGION="us-gov-east-1"`
- `DEFAULT_FILTER_VALUE="*bastion*"`
- `DEFAULT_PROFILE="jam-dev"`

**scan.sh**:

- `ORGANIZATION="sld-45"`
- `EXCLUDE_TAGS="(sha256|nightly|arm64|latest|ubi)"`
- `ARCH="amd64"`

## Development Guidelines

### Shell Script Standards

All scripts adhere to:

- Strict bash error handling (`set -euo pipefail` patterns)
- Full shellcheck compliance with no warnings
- Consistent function naming and documentation
- Proper quoting and variable expansion
- Comprehensive error handling with cleanup

### Testing and Validation

Before committing changes:

1. Run `shellcheck bin/*` to validate syntax and best practices
1. Test scripts in both interactive and non-interactive modes
1. Verify credential handling works with all supported methods
1. Test error conditions and cleanup behavior

### Adding New Scripts

New utility scripts should:

1. Source `common.sh` for consistent output and utilities
1. Include proper usage documentation and help functions
1. Support both interactive and automated execution modes
1. Handle credentials securely using the established patterns
1. Follow the existing color-coded output conventions
