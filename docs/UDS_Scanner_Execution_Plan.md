# UDS Vulnerability Scanner - Unified Execution Plan

## Overview

This document provides a comprehensive analysis and unified execution plan for the UDS vulnerability scanning script (`bin/scan.sh`). The script is a sophisticated 1,392-line Bash utility that scans UDS (Unicorn Delivery Service) packages for container image vulnerabilities using Grype.

## High-Level System Architecture

```mermaid
graph TB
    subgraph "Input & Configuration"
        A[Command Line Args] --> B[Parse Arguments]
        C[versions.json] --> D[Package Discovery]
        E[Environment Variables] --> F[Credential Management]
        G[OnePassword] --> F
    end

    subgraph "Initialization Phase"
        B --> H[Initialize Credentials]
        F --> H
        H --> I[Login to Registries]
        D --> J[Validate Packages]
    end

    subgraph "Processing Pipeline"
        I --> K[Create Working Directory]
        J --> K
        K --> L[Process Packages Loop]

        subgraph "Package Processing"
            L --> M[Pull UDS Package]
            M --> N[Extract OCI Images]
            N --> O[Scan with Grype]
        end

        O --> P[Version Check]
        P --> Q[Store Results]
    end

    subgraph "Output Generation"
        Q --> R[Aggregate Results]
        R --> S[Generate JSON Report]
        S --> T[Create Archive]
        T --> U[Move to Output Dir]
    end

    subgraph "External Dependencies"
        V[Zarf] --> M
        V --> N
        W[Grype Scanner] --> O
        X[Registry APIs] --> P
    end

    style A fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    style C fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    style H fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style L fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style O fill:#ffebee,stroke:#c62828,stroke-width:2px
    style S fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
```

## API Interface Analysis

### Command-Line Interface

```bash
./scan.sh [OPTIONS]

OPTIONS:
  -h, --help              Show help message
  -d, --debug             Enable debug output
  --skip-op               Skip OnePassword credential retrieval
  --skip-version-check    Skip checking for newer image versions
  --skip-validation       Skip package registry validation
  -o, --output DIR        Output directory (default: artifacts/)
  --exclude-tags PATTERN Regex for tag exclusion (default: "(sha256|nightly|arm64|latest|ubi)")
  --arch ARCH            Architecture to scan (default: amd64)
  -y, --yes              Auto-approve all packages (non-interactive)
  --no-interactive       Disable interactive prompts
```

### Configuration Files

**versions.json Structure:**

```json
{
  "packages": [
    {
      "name": "package-name",
      "version": "1.2.3-uds.0-unicorn",
      "environments": ["dev", "staging", "prod"]
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

### Environment Variables

```bash
UDS_USERNAME/UDS_PASSWORD           # UDS registry credentials
IRONBANK_USERNAME/IRONBANK_PASSWORD # Iron Bank credentials
UDS_URL                             # Registry URL (default: registry.defenseunicorns.com)
ORGANIZATION                        # Target organization (default: sld-45)
```

### Output Formats

- **Individual Scan Files**: JSON files per image (from Grype)
- **Combined Report**: `scan-results-{timestamp}.json` with comprehensive metadata
- **Archive**: Compressed tarball of all results
- **Console Output**: Real-time colored progress and status updates

## Technical Architecture

### Key Implementation Patterns

```bash
# Global tracking arrays (declared with -g/-gA flags)
declare -gA image_to_package            # Maps images to package JSON
declare -gA image_to_oci_dir            # Maps images to extracted OCI directories  
declare -gA oci_dir_to_image            # Reverse mapping for OCI processing
declare -gA image_latest_versions       # Version check results
declare -gA registry_has_credentials    # Registry authentication status
```

### Security Features

- **Credential Management**: OnePassword integration with secure fallbacks
- **Registry Authentication**: Secure login using Zarf
- **Package Validation**: Pre-flight verification of package existence
- **Safe File Handling**: Secure filename generation and cleanup

### Performance Optimizations

- **Sequential Processing**: One package at a time with immediate cleanup
- **Temporary Directory Isolation**: Per-package workspace management
- **Memory Efficiency**: Direct OCI scanning without registry push/pull
- **Selective Operations**: Credential-aware version checking

## Unified Execution Plan

## Phase 1: Initialization & Pre-flight Checks

```mermaid
flowchart TD
    A[Start scan.sh] --> B[Parse Command Line Arguments]
    B --> C{Debug Mode?}
    C -->|Yes| D[Set DEBUG=1]
    C -->|No| E[Continue]
    D --> E

    E --> F[Create Output Directory]
    F --> G{Skip OnePassword?}

    subgraph "Credential Management"
        G -->|No| H[Check UDS Credentials]
        H --> I{UDS Creds Available?}
        I -->|No| J[Fetch from OnePassword]
        I -->|Yes| K[Use Existing]
        J --> L[Check Iron Bank Creds]
        K --> L

        L --> M{Iron Bank Creds Available?}
        M -->|No| N[Fetch from OnePassword]
        M -->|Yes| O[Use Existing]
        N --> O
    end

    G -->|Yes| P[Prompt for Missing Credentials]
    O --> P

    P --> Q{Interactive Mode?}
    Q -->|Yes| R[Prompt User for Input]
    Q -->|No| S[Use Environment Variables]
    R --> T
    S --> T[Validate Required Credentials]

    T --> U{All Credentials Valid?}
    U -->|No| V[Error Exit]
    U -->|Yes| W[Login to Iron Bank Registry]

    W --> X{Iron Bank Login Success?}
    X -->|No| Y[Error Exit]
    X -->|Yes| Z[Login to UDS Registry]

    Z --> AA{UDS Login Success?}
    AA -->|No| BB[Error Exit]
    AA -->|Yes| CC[Initialization Complete]

    style A fill:#4caf50,color:white
    style V fill:#f44336,color:white
    style Y fill:#f44336,color:white
    style BB fill:#f44336,color:white
    style CC fill:#2196f3,color:white
    style J fill:#ff9800,color:white
    style N fill:#ff9800,color:white
```

**Key Activities:**

- Parse and validate command-line arguments
- Initialize debug and output settings
- Manage credentials through OnePassword or environment variables
- Authenticate with UDS and Iron Bank registries
- Validate all prerequisites before proceeding

**Dependencies:** OnePassword CLI (optional), Zarf, network connectivity

## Phase 2: Package Discovery & Validation

```mermaid
flowchart TD
    A[Load versions.json] --> B{File Exists?}
    B -->|No| C[Error: File Not Found]
    B -->|Yes| D[Parse JSON Content]

    D --> E{Valid JSON?}
    E -->|No| F[Error: Invalid JSON]
    E -->|Yes| G[Extract Registry Information]

    G --> H[Build Registry Credentials Map]
    H --> I[Extract Packages Array]
    I --> J[Process Each Package]

    subgraph "Package Processing Loop"
        J --> K[Extract Package Details]
        K --> L[Build Registry Path]
        L --> M[Store Package Info]
        M --> N{More Packages?}
        N -->|Yes| J
        N -->|No| O[Package Loading Complete]
    end

    O --> P{Skip Validation?}
    P -->|Yes| Q[Validation Skipped]
    P -->|No| R[Start Package Validation]

    subgraph "Package Validation"
        R --> S[Check Package in Registry]
        S --> T{Package Exists?}
        T -->|No| U[Add to Missing List]
        T -->|Yes| V[Mark as Valid]
        U --> W{More to Validate?}
        V --> W
        W -->|Yes| S
        W -->|No| X{Any Missing?}
    end

    X -->|Yes| Y[Error: Missing Packages]
    X -->|No| Z[All Packages Validated]
    Q --> Z

    Z --> AA[Discovery Complete]

    style C fill:#f44336,color:white
    style F fill:#f44336,color:white
    style Y fill:#f44336,color:white
    style AA fill:#4caf50,color:white
    style Q fill:#ff9800,color:white
```

**Key Activities:**

- Load and parse `versions.json` configuration file
- Extract package definitions and registry mappings
- Build credential awareness map for registries
- Validate package (with version) existence in registries
- Prepare package list for processing

**Data Structures:**

- Registry path construction: `$UDS_URL/$ORGANIZATION/$pkg_name:$pkg_version`
- Global arrays for packages and package_info
- Registry credentials mapping

## Phase 3: Package Processing Pipeline

```mermaid
flowchart TD
    A[Create Working Directory] --> B[Initialize Tracking Arrays]
    B --> C[Start Package Loop]

    subgraph "Package Selection"
        C --> D[Get Next Package]
        D --> E{Interactive Mode?}
        E -->|Yes| F[Prompt User for Confirmation]
        E -->|No| G{Auto-approve All?}
        G -->|Yes| H[Auto-approve]
        G -->|No| I[Skip Package]
        F --> J{User Approved?}
        J -->|No| I
        J -->|Yes| H
        H --> K[Package Approved]
    end

    K --> L[Create Package Temp Directory]
    L --> M[Pull Package with Zarf]

    subgraph "Package Extraction"
        M --> N{Pull Success?}
        N -->|No| O[Track Error]
        N -->|Yes| P[Find Downloaded Package File]
        P --> Q[Extract All OCI Images]
        Q --> R{Images Extracted?}
        R -->|No| S[Log Warning]
        R -->|Yes| T[Clean Up Package File]
    end

    T --> U[Process Extracted Images]

    subgraph "Image Processing Loop"
        U --> V[Get Next OCI Directory]
        V --> W[Map Image to Package]
        W --> X[Update Tracking Arrays]
        X --> Y[Scan Image with Grype]
        Y --> Z{More Images?}
        Z -->|Yes| V
        Z -->|No| AA[Package Processing Complete]
    end

    AA --> BB[Clean Up Package Temp Dir]
    I --> CC{More Packages?}
    O --> CC
    S --> CC
    BB --> CC
    CC -->|Yes| C
    CC -->|No| DD[All Packages Processed]

    style O fill:#f44336,color:white
    style S fill:#ff9800,color:white
    style DD fill:#4caf50,color:white
    style I fill:#9e9e9e,color:white
```

**Key Activities:**

- Interactive or automated package approval workflow
- Package pulling using Zarf OCI operations
- Container image extraction from package archives
- Immediate cleanup to minimize disk usage
- Parallel tracking of image-to-package relationships

**Resource Management:**

- Per-package temporary directories
- Immediate cleanup after image extraction
- Memory-efficient processing patterns

## Phase 4: Vulnerability Scanning & Analysis

```mermaid
flowchart TD
    A[Start Image Scan] --> B[Determine Scan Target]
    B --> C{OCI Directory?}
    C -->|Yes| D[Use oci-dir: prefix]
    C -->|No| E[Use Image Name]

    D --> F[Check for 'latest' Tag]
    E --> F
    F --> G{Has 'latest' Tag?}
    G -->|Yes| H[Skip Scan with Warning]
    G -->|No| I[Proceed with Scan]

    I --> J{Skip Version Check?}
    J -->|No| K[Check Latest Version]
    J -->|Yes| L[Version Check Skipped]

    subgraph "Version Checking"
        K --> M[Parse Image Format]
        M --> N{Parse Success?}
        N -->|No| O[Version Check Failed]
        N -->|Yes| P[Check Registry Credentials]
        P --> Q{Has Credentials?}
        Q -->|No| R[Skip - No Credentials]
        Q -->|Yes| S[Query Registry for Tags]
        S --> T{Query Success?}
        T -->|No| U[Version Check Failed]
        T -->|Yes| V[Compare Versions]
        V --> W{Newer Available?}
        W -->|Yes| X[Report Newer Version]
        W -->|No| Y[Current is Latest]
    end

    L --> Z[Generate Safe Filename]
    O --> Z
    R --> Z
    U --> Z
    X --> Z
    Y --> Z

    Z --> AA[Execute Grype Scan]
    AA --> BB{Grype Success?}
    BB -->|No| CC[Track Scan Error]
    BB -->|Yes| DD[Validate JSON Output]

    DD --> EE{Valid JSON?}
    EE -->|No| FF[Track Scan Error]
    EE -->|Yes| GG[Increment Success Counter]

    GG --> HH[Scan Complete]
    CC --> HH
    FF --> HH
    H --> HH

    style H fill:#ff9800,color:white
    style CC fill:#f44336,color:white
    style FF fill:#f44336,color:white
    style GG fill:#4caf50,color:white
    style HH fill:#2196f3,color:white
```

**Key Activities:**

- Direct scanning of OCI directories with Grype
- Intelligent version pattern matching and comparison
- Registry API queries for latest version information
- Comprehensive error handling for scan failures
- Risk score calculation and vulnerability aggregation

**Version Analysis:**

- Pattern recognition for semantic versioning
- FIPS-aware version filtering
- Architecture-specific tag handling
- Graceful degradation for parsing failures

## Phase 5: Report Generation & Output

```mermaid
flowchart TD
    A[Start Report Generation] --> B[Initialize Counters]
    B --> C[Create Temporary Files]
    C --> D[Process Each Scan Result]

    subgraph "Result Processing Loop"
        D --> E[Validate JSON File]
        E --> F{Valid JSON?}
        F -->|No| G[Skip File]
        F -->|Yes| H[Extract Vulnerability Counts]
        H --> I[Calculate Risk Scores]
        I --> J[Map Image to Package]
        J --> K[Update Package Counters]
        K --> L[Track Outdated Images]
        L --> M[Append to Combined Results]
        M --> N{More Files?}
        N -->|Yes| D
        N -->|No| O[Processing Complete]
        G --> N
    end

    O --> P[Calculate Total Statistics]
    P --> Q[Create Enhanced Package JSON]
    Q --> R[Build Final Report Structure]

    subgraph "Report Structure"
        R --> S[Add Metadata Section]
        S --> T[Add Summary Section]
        T --> U[Add Package Details]
        U --> V[Add Vulnerability Results]
        V --> W[Add Error Information]
    end

    W --> X[Update JSON File]
    X --> Y{Update Success?}
    Y -->|No| Z[Warning: Malformed JSON]
    Y -->|Yes| AA[Create Results Archive]

    AA --> BB[Move Files to Output Directory]
    BB --> CC[Clean Up Temporary Files]
    CC --> DD[Report Generation Complete]
    Z --> DD

    style G fill:#ff9800,color:white
    style Z fill:#ff9800,color:white
    style DD fill:#4caf50,color:white
```

**Report Structure:**

```json
{
  "metadata": {
    "scanTimestamp": "2024-01-15T10:30:00Z",
    "scanDurationSeconds": 1847,
    "totalImagesScanned": 45,
    "successfulScans": 42,
    "failedScans": 3,
    "grypeVersion": "0.73.4"
  },
  "summary": {
    "packages": [...],
    "totalPackages": 18,
    "vulnerabilitiesBySeverity": {
      "critical": 12,
      "high": 34,
      "medium": 156,
      "low": 89,
      "negligible": 23,
      "unknown": 5
    },
    "totalVulnerabilities": 319,
    "fixableVulnerabilities": 284,
    "unfixableVulnerabilities": 35,
    "totalRisk": 1250.5,
    "errors": [...]
  },
  "results": [...]
}
```

## Data Flow Architecture

```mermaid
graph LR
    subgraph "Input Data"
        A[versions.json] --> B[Package Definitions]
        C[Environment Variables] --> D[Credentials]
        E[OnePassword] --> D
        F[Command Args] --> G[Configuration]
    end

    subgraph "Processing Flow"
        B --> H[Package Registry Paths]
        D --> I[Registry Authentication]
        G --> J[Scan Parameters]

        H --> K[Zarf Package Pull]
        I --> K
        K --> L[OCI Image Archives]

        L --> M[Image Extraction]
        M --> N[OCI Directory Structure]

        N --> O[Grype Vulnerability Scan]
        J --> O
        O --> P[JSON Scan Results]
    end

    subgraph "Data Transformation"
        P --> Q[Result Aggregation]
        Q --> R[Vulnerability Counts]
        Q --> S[Risk Calculations]
        Q --> T[Package Mappings]

        R --> U[Summary Statistics]
        S --> U
        T --> U

        U --> V[Enhanced Package Data]
        V --> W[Final JSON Report]
    end

    subgraph "Output Data"
        W --> X[Comprehensive Scan Report]
        P --> Y[Individual Scan Files]
        Y --> Z[Compressed Archive]
        X --> AA[artifacts/ Directory]
        Z --> AA
    end

    style A fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style P fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style W fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    style AA fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
```

## Error Handling & Recovery

```mermaid
flowchart TD
    A[Error Detected] --> B{Error Type?}

    B -->|Credential Error| C[Credential Failure]
    B -->|Network Error| D[Network Failure]
    B -->|Package Error| E[Package Processing Error]
    B -->|Scan Error| F[Grype Scan Error]
    B -->|File System Error| G[File System Error]

    subgraph "Credential Error Handling"
        C --> C1{OnePassword Available?}
        C1 -->|Yes| C2[Retry with OnePassword]
        C1 -->|No| C3[Prompt User Input]
        C2 --> C4{Retry Success?}
        C3 --> C4
        C4 -->|Yes| C5[Continue Processing]
        C4 -->|No| C6[Exit with Error]
    end

    subgraph "Network Error Handling"
        D --> D1[Log Network Error]
        D1 --> D2{Critical Operation?}
        D2 -->|Yes| D3[Exit with Error]
        D2 -->|No| D4[Skip and Continue]
    end

    subgraph "Package Error Handling"
        E --> E1[Track Package Error]
        E1 --> E2[Add to Error Report]
        E2 --> E3[Skip Package]
        E3 --> E4[Continue with Next]
    end

    subgraph "Scan Error Handling"
        F --> F1[Track Scan Error]
        F1 --> F2{Authentication Error?}
        F2 -->|Yes| F3[Report Auth Issue]
        F2 -->|No| F4[Report Scan Failure]
        F3 --> F5[Add to Error Collection]
        F4 --> F5
        F5 --> F6[Continue with Next Image]
    end

    subgraph "File System Error Handling"
        G --> G1{Critical File?}
        G1 -->|Yes| G2[Exit with Error]
        G1 -->|No| G3[Log Warning]
        G3 --> G4[Attempt Recovery]
        G4 --> G5{Recovery Success?}
        G5 -->|Yes| G6[Continue Processing]
        G5 -->|No| G7[Degrade Gracefully]
    end

    subgraph "Cleanup & Recovery"
        H[Cleanup Operations] --> I[Remove Temp Directories]
        I --> J[Close File Handles]
        J --> K[Generate Error Report]
        K --> L[Exit with Appropriate Code]
    end

    C5 --> M[Return to Main Flow]
    C6 --> H
    D3 --> H
    D4 --> M
    E4 --> M
    F6 --> M
    G2 --> H
    G6 --> M
    G7 --> M

    style C6 fill:#f44336,color:white
    style D3 fill:#f44336,color:white
    style G2 fill:#f44336,color:white
    style M fill:#4caf50,color:white
    style L fill:#ff5722,color:white
```

## Critical Dependencies & Requirements

### External Tools

- **Zarf**: Package operations and registry authentication
- **Grype**: Vulnerability scanning engine
- **jq**: JSON processing and manipulation
- **OnePassword CLI**: Optional credential management

### System Requirements

- Bash 4.0+ with associative array support
- Sufficient disk space for temporary OCI image storage
- Network connectivity to UDS and Iron Bank registries
- Write permissions for artifacts directory

### Configuration Requirements

- Valid `versions.json` with package definitions
- Registry credentials (OnePassword, environment variables, or interactive)
- Appropriate architecture selection (amd64/arm64)

## Key Technical Strengths

1. **Robust Error Handling**: Package-level failures don't stop entire scans
1. **Security-First Design**: Secure credential management with multiple fallback options
1. **Performance Optimized**: Sequential processing with immediate cleanup to minimize resource usage
1. **Enterprise Ready**: Support for multiple registries, architectures, and FIPS compliance
1. **Comprehensive Reporting**: Detailed vulnerability attribution back to specific packages and environments
1. **Interactive & Automated**: Flexible execution modes for different use cases

## Usage Examples

### Basic Interactive Scan

```bash
./bin/scan.sh
```

### Automated Non-Interactive Scan

```bash
./bin/scan.sh -y --skip-op --output /tmp/scan-results
```

### Debug Mode with Custom Architecture

```bash
./bin/scan.sh --debug --arch arm64 --exclude-tags "(nightly|rc)"
```

### Skip Version Checking for Faster Scans

```bash
./bin/scan.sh --skip-version-check --skip-validation
```

This unified execution plan provides a comprehensive framework for understanding and operating the sophisticated UDS vulnerability scanning system, enabling both operational use and further development.
