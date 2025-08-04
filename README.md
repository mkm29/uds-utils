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

A vulnerability scanning tool that uses Grype to scan container images from UDS packages. It dynamically discovers packages from your registry, pulls the packages, extracts embedded OCI images, and scans them directly without needing to push/pull individual images to/from registries.

#### Prerequisites

The script requires registry credentials for both UDS and Iron Bank registries. You can either set environment variables or the script will prompt you:

```bash
# Option 1: Set environment variables
export UDS_USERNAME="your-username"
export UDS_PASSWORD="your-password"
export UDS_URL="registry.defenseunicorns.com"
export ORGANIZATION="sld-45"  # Optional, defaults to sld-45

# Iron Bank credentials (optional, but recommended)
export IRONBANK_USERNAME="your-ironbank-username"
export IRONBANK_PASSWORD="your-ironbank-password"
export IRONBANK_URL="registry1.dso.mil"  # Optional, defaults to registry1.dso.mil

# Option 2: Let the script prompt you for missing values
./bin/scan.sh

# Option 3: Use OnePassword (default behavior if credentials not set)
# The script will automatically fetch credentials from OnePassword
# Use --skip-op to disable this behavior
```

#### Basic Usage

```bash
# Run vulnerability scan with default settings
./bin/scan.sh

# Run with debug output
./bin/scan.sh --debug

# Skip OnePassword credential retrieval (use env vars or prompts)
./bin/scan.sh --skip-op

# Skip version checking for faster scans
./bin/scan.sh --skip-version-check

# Custom output directory
./bin/scan.sh --output /path/to/results

# Exclude release candidate tags from version checking
./bin/scan.sh --exclude-tags "(sha256|nightly|arm64|latest|rc)"

# Specify target architecture (default: amd64)
./bin/scan.sh --arch arm64

# Show help
./bin/scan.sh --help
```

#### Command Line Options

- `-h, --help` - Show help message and usage information
- `-d, --debug` - Enable debug output for troubleshooting
- `--skip-op` - Skip OnePassword credential retrieval (useful in CI/CD environments)
- `--skip-version-check` - Skip checking for newer image versions (speeds up scanning)
- `-o, --output DIR` - Specify output directory (default: `artifacts/`)
- `--exclude-tags PATTERN` - Regex pattern for tags to exclude from version checking (default: `"(sha256|nightly|arm64|latest)"`)
- `--arch ARCH` - Specify target architecture for scanning (default: `amd64`)

The script will:

- Connect to your registry and discover all packages in the organization
- Find the latest version of each package (prioritizing -unicorn tags)
- Pull each package using `zarf package pull`
- Extract embedded OCI images from the package archives
- Scan each extracted OCI image directly using `grype oci-dir:<path>` for better performance
- Check for newer versions with intelligent filtering:
  - Architecture-specific tags (e.g., v1.2.3-arm64) are excluded when checking versions
  - FIPS-certified images only compare against other FIPS versions
  - Version patterns are matched to prevent unrelated tags from being considered
- Generate a comprehensive report with proper package attribution

Note: The script includes all package discovery logic internally, so `get_tags.sh` is not required.

#### Color-Coded Output

The script provides color-coded terminal output for better readability:

- **Blue**: Progress indicators and informational messages
- **Green**: Image names and success messages
- **Yellow**: Warnings and newer version notifications
- **Red**: Errors and failures
- **White**: General text and scan details

#### Output Files

All output files are saved to the `artifacts/` directory:

- `images.txt` - List of all unique images found
- `scan-results.json` - Aggregated vulnerability report with:
  - Complete package information (name, version, registry) for all discovered packages
  - Vulnerability summary by severity for each package including totalRisk
  - List of outdated images for each package with current and latest versions
  - Each image result includes its source package details
  - Version check information showing if images are up-to-date or outdated
  - Overall vulnerability counts by severity
  - Risk scores and fixability metrics
  - Errors section listing failed scans with package and image information
- `scan_results_YYYYMMDD_HHMMSS.tar.gz` - Archive of all scan results
- `errors.txt` - Images that failed to scan (if any)

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

A tool for generating a Kubernetes Bill of Materials (KBOM) using Trivy to scan cluster resources.

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
- ✅ Full shellcheck compliance

### scan.sh

- ✅ Batch vulnerability scanning for OCI packages
- ✅ Package pulling and OCI image extraction from Zarf packages
- ✅ Direct scanning of extracted OCI directories (no registry push/pull needed)
- ✅ Proper package attribution for all vulnerabilities
- ✅ Comprehensive vulnerability reporting with severity levels
- ✅ Risk score calculation and fixability analysis
- ✅ Intelligent version checking:
  - Architecture-aware filtering (excludes arch-specific tags)
  - FIPS version filtering (FIPS images only compare to FIPS)
  - Pattern-based version matching to prevent false positives
  - Works with images that have proper OCI annotations
- ✅ Architecture support with --arch flag (default: amd64)
- ✅ Color-coded terminal output for better readability
- ✅ Command-line options for flexible usage
- ✅ OnePassword integration for secure credential management
- ✅ Support for multiple registries (UDS and Iron Bank)
- ✅ Debug mode for troubleshooting
- ✅ Configurable output directory
- ✅ JSON and archived output formats
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

- ✅ Kubernetes cluster vulnerability scanning
- ✅ Namespace-level granularity
- ✅ Automatic Zarf registry port-forwarding
- ✅ Configurable severity filtering
- ✅ Interactive configuration wizard
- ✅ Summary report generation
- ✅ Full shellcheck compliance

## Prerequisites

### For uds-ssm

- AWS CLI v2 installed and configured
- AWS Session Manager Plugin
- kubectl (for Kubernetes operations)
- Appropriate AWS IAM permissions for EC2, EKS, and SSM

### For scan.sh

- [Zarf](https://zarf.dev/) - For package pulling and inspection
- [Grype](https://github.com/anchore/grype) - For vulnerability scanning (with OCI directory support)
- jq - For JSON processing and OCI manifest parsing
- bc - For floating point calculations
- curl - For registry API calls
- tar - For extracting package archives
- OnePassword CLI (optional) - For secure credential management
- Valid credentials for accessing OCI registries (UDS and Iron Bank)

### For letscerts.sh

- [Certbot](https://certbot.eff.org/) - For Let's Encrypt certificate generation (auto-installed if missing)
- Internet connectivity - For Let's Encrypt API access
- DNS or HTTP access - For domain validation

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
