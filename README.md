# UDS Utils

A collection of utility scripts for interacting with UDS (Unicorn Delivery Service) systems, including AWS SSM tunneling for EKS access and container image vulnerability scanning.

## Table of Contents

- [UDS Utils](#uds-utils)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
    - [uds-ssm](#uds-ssm)
      - [Basic Commands](#basic-commands)
      - [Advanced Usage](#advanced-usage)
    - [scan.sh](#scansh)
      - [Basic Usage](#basic-usage)
      - [Configuration](#configuration)
      - [Output Files](#output-files)
  - [Features](#features)
    - [uds-ssm](#uds-ssm-1)
    - [scan.sh](#scansh-1)
  - [Prerequisites](#prerequisites)
    - [For uds-ssm](#for-uds-ssm)
    - [For scan.sh](#for-scansh)
  - [Configuration](#configuration-1)
    - [uds-ssm Defaults](#uds-ssm-defaults)
    - [Session State](#session-state)
  - [Contributing](#contributing)
  - [License](#license)
  - [Acknowledgments](#acknowledgments)
  - [Support](#support)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/mkm29/uds-utils.git
cd uds-utils
```

2. Make the scripts executable:

```bash
chmod +x bin/uds-ssm bin/scan.sh
```

3. Add the `bin` directory to your PATH for global access:

```bash
echo 'export PATH="$PATH:'"$(pwd)/bin"'"' >> ~/.bashrc
source ~/.bashrc
```

## Usage

### uds-ssm

A utility for establishing secure tunnels to EC2 instances to perform local kubectl operations with EKS clusters.

#### Basic Commands

```bash
# Start a port forwarding session
uds-ssm start

# Start with custom cluster and region
uds-ssm start --cluster-name my-cluster --region us-west-2

# Create and configure kubeconfig
uds-ssm start --kubeconfig --merge

# Start an interactive SSH session
uds-ssm ssh

# Check status of active sessions
uds-ssm status

# Stop a specific session
uds-ssm stop --session-id ssm-1234567890-12345

# Stop all sessions
uds-ssm stop --all
```

#### Advanced Usage

```bash
# Use specific instance ID instead of filter
uds-ssm start --instance-id i-1234567890abcdef0

# Custom AWS profile
uds-ssm start --profile production

# View session logs
uds-ssm logs --session-id ssm-1234567890-12345

# Get environment variables for kubectl
eval $(uds-ssm env --session-id ssm-1234567890-12345)
```

### scan.sh

A vulnerability scanning tool that uses Grype to scan container images from UDS packages. It dynamically discovers packages from your registry.

#### Prerequisites

The script requires registry credentials. You can either set environment variables or the script will prompt you:

```bash
# Option 1: Set environment variables
export UDS_USERNAME="your-username"
export UDS_PASSWORD="your-password"
export UDS_URL="registry.defenseunicorns.com"
export ORGANIZATION="sld-45"  # Optional, defaults to sld-45

# Option 2: Let the script prompt you for missing values
./bin/scan.sh
```

#### Basic Usage

```bash
# Run vulnerability scan (packages are discovered automatically)
./bin/scan.sh
```

The script will:
- Connect to your registry and discover all packages in the organization
- Find the latest version of each package (prioritizing -unicorn tags)
- Extract all images from the discovered packages
- Scan each image for vulnerabilities
- Generate a comprehensive report

Note: The script includes all package discovery logic internally, so `get_tags.sh` is not required.

#### Output Files

All output files are saved to the `artifacts/` directory:

- `images.txt` - List of all unique images found
- `scan-results.json` - Aggregated vulnerability report with:
  - Complete package information (name, version, registry) for all discovered packages
  - Vulnerability summary by severity for each package including totalRisk
  - Each image result includes its source package details
  - Overall vulnerability counts by severity
  - Risk scores and fixability metrics
- `scan_results_YYYYMMDD_HHMMSS.tar.gz` - Archive of all scan results
- `errors.txt` - Images that failed to scan (if any)

### generate-kbom.sh

A tool for generating a Kubernetes Bill of Materials (KBOM) using Trivy to scan cluster resources.

#### Basic Usage

```bash
# Run KBOM generation (interactive prompts)
./bin/generate-kbom.sh
```

#### Features

- Interactive configuration prompts
- Automatic port-forwarding to Zarf registry
- Namespace-specific or cluster-wide scanning
- Configurable vulnerability severity levels
- Summary report generation

#### Output

The KBOM report is saved to `artifacts/<cluster-name>-kbom.txt`

### get_tags.sh

A standalone utility script for discovering packages and their tags from your UDS registry. While `scan.sh` includes its own package discovery logic, this script is useful for exploring available packages and tags.

#### Prerequisites

The script will prompt for any missing values:
- `UDS_USERNAME` - Registry username
- `UDS_PASSWORD` - Registry password  
- `UDS_URL` - Registry URL
- `ORGANIZATION` - Organization to scan (defaults to sld-45)

#### Basic Usage

```bash
# Display all packages and their latest versions
./bin/get_tags.sh

# Output just the package URLs (package mode)
OUTPUT_MODE=packages ./bin/get_tags.sh
```

## Features

### uds-ssm

- ✅ AWS SSM port forwarding to EKS clusters
- ✅ Interactive SSH sessions with automatic user switching
- ✅ Persistent session management
- ✅ Automatic kubeconfig generation and management
- ✅ Session status monitoring and logging
- ✅ Multiple concurrent sessions support

### scan.sh

- ✅ Batch vulnerability scanning for OCI packages
- ✅ Automatic image extraction from Zarf packages
- ✅ Comprehensive vulnerability reporting with severity levels
- ✅ Risk score calculation and fixability analysis
- ✅ JSON and archived output formats
- ✅ Error handling and retry logic

### generate-kbom.sh

- ✅ Kubernetes cluster vulnerability scanning
- ✅ Namespace-level granularity
- ✅ Automatic Zarf registry port-forwarding
- ✅ Configurable severity filtering
- ✅ Interactive configuration wizard
- ✅ Summary report generation

## Prerequisites

### For uds-ssm

- AWS CLI v2 installed and configured
- AWS Session Manager Plugin
- kubectl (for Kubernetes operations)
- Appropriate AWS IAM permissions for EC2, EKS, and SSM

### For scan.sh

- [Zarf](https://zarf.dev/) - For package inspection
- [Grype](https://github.com/anchore/grype) - For vulnerability scanning
- jq - For JSON processing
- Valid credentials for accessing OCI registries

### For generate-kbom.sh

- [Trivy](https://github.com/aquasecurity/trivy) - For Kubernetes scanning
- kubectl - Configured with cluster access
- yq - For YAML processing
- jq - For JSON processing
- Zarf registry running in cluster

## Configuration

### uds-ssm Defaults

Default values can be modified at the top of the script:

```bash
DEFAULT_CLUSTER_NAME="uds-eks-dev-uds"
DEFAULT_REGION="us-gov-east-1"
DEFAULT_FILTER_VALUE="*bastion*"
DEFAULT_PROFILE="jam-dev"
```

### Session State

uds-ssm stores session information in `~/.local/state/udsm/` for persistence across command invocations.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
1. Create your feature branch (`git checkout -b feature/AmazingFeature`)
1. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
1. Push to the branch (`git push origin feature/AmazingFeature`)
1. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for use with [UDS (Unicorn Delivery Service)](https://github.com/defenseunicorns/uds-core)
- Uses [Grype](https://github.com/anchore/grype) for vulnerability scanning
- Leverages AWS Systems Manager for secure connectivity

## Support

For issues, questions, or contributions, please open an issue in the GitHub repository.
