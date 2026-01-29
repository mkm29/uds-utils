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
chmod +x bin/uds-ssm bin/scan.sh bin/letscerts.sh bin/generate-kbom.sh bin/get_tags.sh
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

A vulnerability scanning tool that extracts Software Bills of Materials (SBOMs) from UDS packages and scans them using Grype to generate CSV-formatted vulnerability reports.

#### Prerequisites

The script requires the following tools:

- [UDS CLI](https://github.com/defenseunicorns/uds-cli) - For package inspection and SBOM extraction
- [Grype](https://github.com/anchore/grype) - For vulnerability scanning of SBOMs
- jq - For JSON processing
- A packages.txt file containing the list of packages to scan (format: `package:version` on each line)

#### Basic Usage

```bash
# Run vulnerability scan with default settings (uses ./packages.txt)
./bin/scan.sh

# Specify a custom packages file
./bin/scan.sh /path/to/custom-packages.txt
```

#### Configuration

You can configure the script behavior using these environment variables:

- `REGISTRY` - Registry URL (default: registry.defenseunicorns.com)
- `ORG` - Organization name (default: sld-45)
- `ARCH` - Target architecture (default: amd64)

```bash
# Example with custom settings
REGISTRY=myregistry.com ORG=myorg ARCH=arm64 ./bin/scan.sh
```

#### Package File Format

The packages.txt file should contain one package per line in the format `package:version`:

```
core-base:0.52.0-unicorn
core-identity-authorization:0.52.0-unicorn
gitlab-runner:18.2.0-uds.1-unicorn
headlamp:0.35.0-uds.0-registry1
init:v0.61.2
```

The script will:

1. Read package names and versions from the packages file (default: `./packages.txt`)
1. For each package, extract SBOMs using `uds zarf package inspect sbom`
1. Scan each SBOM with Grype using a custom CSV template
1. Generate individual CSV reports for each package
1. Create a master CSV report combining all vulnerabilities
1. Package all reports into a compressed tarball

#### Output Files

All output files are created in a temporary working directory and packaged into:

- **Individual CSV reports** - One per package with format: `{package_name}.csv`
- **Master report** - `ALL_VULNERABILITIES.csv` containing all unique vulnerabilities
- **Tarball** - `zarf-scan-reports.tar.gz` in the project root containing all reports

#### CSV Report Format

Each CSV report contains the following columns:

- Package - The vulnerable package/component name
- Version - Current version of the vulnerable package
- Fixed Version - Version that fixes the vulnerability (if available)
- Type - Package type (e.g., rpm, deb, npm, etc.)
- CVE ID - Common Vulnerabilities and Exposures identifier
- Severity - Vulnerability severity (Critical, High, Medium, Low)

### letscerts.sh

A convenient tool for generating Let's Encrypt SSL certificates using Certbot with DNS or HTTP challenges.

#### Basic Usage

```bash
# Generate certificate with DNS challenge (interactive)
./bin/letscerts.sh --domains "example.com www.example.com" --email admin@example.com

# Use staging server for testing
./bin/letscerts.sh --domains "example.com" --email admin@example.com --staging

# Use HTTP challenge instead of DNS
./bin/letscerts.sh --domains "example.com" --email admin@example.com --challenge HTTP

# Custom key size
./bin/letscerts.sh --domains "example.com" --email admin@example.com --key-size 2048
```

#### Command Line Options

- `-h, --help` - Display help message
- `--domains` - Space-separated list of domains to include in the certificate
- `--email` - Email address for Let's Encrypt registration
- `--staging` - Use Let's Encrypt staging server (for testing)
- `--production` - Use Let's Encrypt production server (default)
- `--challenge` - Challenge type: DNS (default) or HTTP
- `--key-size` - RSA key size (default: 4096)

#### Features

- Automatic Certbot installation if not present
- Support for both DNS and HTTP challenges
- Staging server support for testing
- Organized certificate storage in `~/.letsencrypt/`
- Color-coded output for better readability
- Full shellcheck compliance

#### Output

Certificates are stored in:

- Configuration: `~/.letsencrypt/config/`
- Working directory: `~/.letsencrypt/work/`
- Logs: `~/.letsencrypt/log/`

### get_tags.sh

A standalone utility script for discovering packages and their tags from your UDS registry. While `scan.sh` includes its own package discovery logic, this script is useful for exploring available packages and tags.

### generate-kbom.sh

A tool for generating a Kubernetes Bill of Materials (KBOM) using Trivy to scan Kubernetes cluster resources for vulnerabilities. The KBOM provides a comprehensive security assessment of all workloads running in specified namespaces.

#### Prerequisites

The script requires the following tools and access:

- [Trivy](https://github.com/aquasecurity/trivy) - For Kubernetes cluster scanning
- kubectl - Configured with cluster access
- yq - For YAML processing
- nc (netcat) - For port connectivity testing
- Access to a Kubernetes cluster with a running Zarf Docker registry

#### Interactive Configuration

The script uses an interactive wizard to gather configuration:

```bash
# Run the KBOM generation script
./bin/generate-kbom.sh
```

You'll be prompted for:

- **Kubeconfig Path**: Absolute path to your kubeconfig file
- **Kubernetes Context**: Target context name (default: `uds-eks-test-uds-context`)
- **Zarf Registry Service**: Service name for Zarf Docker registry (default: `zarf-docker-registry`)
- **Zarf Registry Port**: Port for registry access (default: `31999`)
- **Namespaces**: Comma-separated list of namespaces to scan (default: all namespaces)
- **Output Filename**: Name for the KBOM report (default: `{cluster-name}-kbom.txt`)
- **Severity Levels**: Vulnerability severities to include (default: `CRITICAL,HIGH`)

#### Features

The script automatically:

1. **Context Switching**: Switches to the specified Kubernetes context
1. **Port Forwarding**: Establishes port forwarding to the Zarf Docker registry
1. **Namespace Discovery**: Retrieves all namespaces if "all" is specified
1. **Trivy Scanning**: Performs comprehensive vulnerability scanning using:
   - Summary report format
   - Table output format
   - Configurable severity filtering
   - 10-minute timeout for large clusters
   - Unfixed vulnerability filtering
1. **Cleanup**: Automatically terminates port forwarding on exit

#### Output

The KBOM report is saved to the `artifacts/` directory and includes:

- **Summary format**: High-level vulnerability overview
- **Table format**: Detailed vulnerability information
- **Namespace-specific results**: Vulnerabilities organized by namespace
- **Severity filtering**: Only includes specified severity levels
- **Execution metrics**: Total scan time and completion status

#### Example Usage

```bash
# Generate KBOM for all namespaces with default settings
./bin/generate-kbom.sh

# The script will interactively prompt for:
# - Kubeconfig: /path/to/kubeconfig
# - Context: my-cluster-context
# - Registry: zarf-docker-registry:31999
# - Namespaces: all (or specific: namespace1,namespace2)
# - Severity: CRITICAL,HIGH,MEDIUM
```

#### Output Files

- `{cluster-name}-kbom.txt` - Complete KBOM report in the `artifacts/` directory

### detect_platform.sh

A cross-platform utility for detecting and normalizing operating system and CPU architecture information. Useful for platform-specific operations and multi-architecture deployments.

#### Basic Usage

```bash
# Get combined platform string (default)
./bin/detect_platform.sh
# Output: linux-amd64, darwin-arm64, etc.

# Get only operating system
./bin/detect_platform.sh os
# Output: linux, darwin, windows

# Get only CPU architecture
./bin/detect_platform.sh arch
# Output: amd64, arm64, arm, 386

# Show OS and architecture separately
./bin/detect_platform.sh --separate
# Output: OS: linux
#         Architecture: amd64

# Show detailed information including raw values
./bin/detect_platform.sh --detailed
# Output: Raw OS: Linux
#         Raw Architecture: x86_64
#         Normalized OS: linux
#         Normalized Architecture: amd64
#         Platform String: linux-amd64
```

#### Command Line Options

- `os`, `--os` - Show only the operating system
- `arch`, `--arch` - Show only the CPU architecture
- `-s`, `--separate` - Show OS and architecture separately
- `-d`, `--detailed` - Show detailed information including raw and normalized values
- `-h`, `--help` - Display help and usage information

#### Supported Platforms

**Operating Systems:**

- Linux → `linux`
- macOS/Darwin → `darwin`
- Windows (MinGW/MSYS/Cygwin) → `windows`

**CPU Architectures:**

- Intel/AMD 64-bit (x86_64, amd64) → `amd64`
- ARM 64-bit (aarch64, arm64) → `arm64`
- ARM 32-bit (armv7l, armv7) → `arm`
- Intel/AMD 32-bit (i386, i686) → `386`

#### Common Platform Strings

- `linux-amd64` - Linux on Intel/AMD 64-bit
- `linux-arm64` - Linux on ARM 64-bit (Raspberry Pi 4, AWS Graviton)
- `darwin-amd64` - macOS on Intel processors
- `darwin-arm64` - macOS on Apple Silicon (M1/M2/M3/M4)
- `windows-amd64` - Windows on Intel/AMD 64-bit

#### Integration with Other Scripts

The script exports its functions for use in other scripts:

```bash
# Source the script to use functions
source ./bin/detect_platform.sh

# Use exported functions
current_os=$(get_os)
current_arch=$(get_arch)
platform=$(get_platform)
```

## Features

### uds-ssm

- ✅ AWS SSM port forwarding to EKS clusters
- ✅ Interactive SSH sessions with automatic user switching
- ✅ Persistent session management
- ✅ Automatic kubeconfig generation and management
- ✅ Session status monitoring and logging
- ✅ Multiple concurrent sessions support
- ✅ Full shellcheck compliance

### scan.sh

- ✅ SBOM-based vulnerability scanning for UDS packages
- ✅ CSV-formatted vulnerability reports
- ✅ Package-by-package SBOM extraction using UDS CLI
- ✅ Grype integration for comprehensive vulnerability scanning
- ✅ Individual and master vulnerability reports
- ✅ Configurable registry, organization, and architecture
- ✅ Color-coded terminal output for better readability
- ✅ Compressed tarball output for easy sharing
- ✅ Duplicate vulnerability removal
- ✅ Detailed vulnerability metrics per package
- ✅ Error handling and retry logic
- ✅ Full shellcheck compliance

### letscerts.sh

- ✅ Let's Encrypt certificate generation
- ✅ DNS and HTTP challenge support
- ✅ Staging server support for testing
- ✅ Automatic Certbot installation
- ✅ Organized certificate management
- ✅ Color-coded output
- ✅ Full shellcheck compliance

### generate-kbom.sh

- ✅ Interactive KBOM (Kubernetes Bill of Materials) generation
- ✅ Comprehensive Kubernetes cluster vulnerability scanning
- ✅ Namespace-level scanning with configurable scope
- ✅ Automatic Zarf Docker registry port-forwarding
- ✅ Configurable vulnerability severity filtering
- ✅ Context switching and kubeconfig management
- ✅ Table and summary report formats
- ✅ Automatic cleanup and error handling
- ✅ Performance metrics and timing
- ✅ Full shellcheck compliance

### detect_platform.sh

- ✅ Cross-platform OS and architecture detection
- ✅ Normalized platform string generation
- ✅ Multiple output formats (combined, separate, detailed)
- ✅ Raw and normalized value display
- ✅ Exportable functions for script integration
- ✅ Support for Linux, macOS, and Windows
- ✅ Multi-architecture support (amd64, arm64, arm, 386)
- ✅ Comprehensive help and usage information
- ✅ Full shellcheck compliance

## Prerequisites

### For uds-ssm

- AWS CLI v2 installed and configured
- AWS Session Manager Plugin
- kubectl (for Kubernetes operations)
- Appropriate AWS IAM permissions for EC2, EKS, and SSM

### For scan.sh

- [UDS CLI](https://github.com/defenseunicorns/uds-cli) - For package inspection and SBOM extraction
- [Grype](https://github.com/anchore/grype) - For vulnerability scanning of SBOMs
- jq - For JSON processing

### For letscerts.sh

- [Certbot](https://certbot.eff.org/) - For Let's Encrypt certificate generation (auto-installed if missing)
- Internet connectivity - For Let's Encrypt API access
- DNS or HTTP access - For domain validation

### For generate-kbom.sh

- [Trivy](https://github.com/aquasecurity/trivy) - For Kubernetes cluster scanning
- kubectl - Configured with cluster access
- yq - For YAML processing
- nc (netcat) - For port connectivity testing
- Access to a Kubernetes cluster with a running Zarf Docker registry

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

### Common Functions

All scripts leverage a shared `common.sh` file that provides:

- Consistent color-coded output functions (info, error, warning, success, debug)
- Platform detection (OS and architecture)
- Package manager abstraction for cross-platform installations
- Registry login utilities
- Argument parsing helpers
- Project path management
- OCI image extraction utilities:
  - `extract_oci_image` - Extract a single OCI image from a package by manifest digest
  - `extract_all_oci_images` - Extract all OCI images from a package and return their paths with image names

## Code Quality

All scripts in this repository:

- ✅ Pass shellcheck validation with no errors or warnings
- ✅ Follow bash best practices
- ✅ Include comprehensive error handling
- ✅ Are well-documented with inline comments

To verify code quality:

```bash
shellcheck bin/*
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
1. Create your feature branch (`git checkout -b feature/AmazingFeature`)
1. Ensure your code passes shellcheck (`shellcheck your-script.sh`)
1. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
1. Push to the branch (`git push origin feature/AmazingFeature`)
1. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for use with [UDS (Unicorn Delivery Service)](https://github.com/defenseunicorns/uds-core)
- Uses [Grype](https://github.com/anchore/grype) for vulnerability scanning
- Uses [Certbot](https://certbot.eff.org/) for Let's Encrypt certificate generation
- Leverages AWS Systems Manager for secure connectivity

## Support

For issues, questions, or contributions, please open an issue in the GitHub repository.
