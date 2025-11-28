# Shai-Hulud NPM Supply Chain Attack Detector

---

## ⚠️ **BETA DRAFT - USE AT YOUR OWN RISK** ⚠️

> **🚨 IMPORTANT DISCLAIMER 🚨**
>
> **THIS IS A BETA DRAFT VERSION. NO RESPONSIBILITY, WARRANTIES, OR GUARANTEES ARE PROVIDED.**
>
> - ❌ **NOT PRODUCTION READY** - This tool is in active development
> - ❌ **NO LIABILITY** - Authors assume no responsibility for any damage, data loss, or security issues
> - ❌ **NO GUARANTEES** - Detection accuracy, completeness, or functionality are not guaranteed
> - ❌ **USE AT YOUR OWN RISK** - Always verify findings manually before taking action
> - ✅ **PROVIDED "AS IS"** - No warranty of any kind, express or implied
>
> **By using this tool, you acknowledge and accept all risks associated with its use.**

---

## ⭐ **POWERSHELL PORT OF ORIGINAL WORK BY [COBENIAN](https://github.com/Cobenian/shai-hulud-detect)** ⭐

> ### **🔴 ALL CREDIT TO ORIGINAL AUTHOR: [Cobenian](https://github.com/Cobenian)** 🔴
>
> **Original Bash Script:** [shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)
>
> **This is a PowerShell port only.** All detection logic, malware signatures, and database are from Cobenian's work.

---

A PowerShell-based security scanner designed to detect compromised npm packages and malicious supply chain attacks, specifically targeting the "Shai-Hulud" attack campaign and its variants.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Original](https://img.shields.io/badge/Original-Bash%20Script%20by%20Cobenian-orange.svg)](https://github.com/Cobenian/shai-hulud-detect)

## 🎯 What It Detects

This scanner identifies multiple supply chain attack patterns:

- **1676+ Compromised npm Packages** - Known malicious package versions
- **Malicious GitHub Actions Workflows** - Backdoored CI/CD pipelines
- **Cryptocurrency Theft Patterns** - Wallet address replacement malware
- **Credential Harvesting Scripts** - TruffleHog abuse and secret exfiltration
- **Destructive Payloads** - Data destruction patterns
- **November 2025 Bun Attack** - Fake Bun runtime installation malware
- **Typosquatting Attacks** (Paranoid Mode) - Package name impersonation
- **Network Exfiltration** (Paranoid Mode) - Data exfiltration patterns

## 📋 Requirements

### System Requirements
- **Windows** 10/11 or Windows Server 2016+
- **PowerShell** 5.1 or higher
- **Administrator Privileges** (automatically requested)

### Optional (Recommended)
- **Node.js** - For npm environment analysis
- **npm** - For package verification
- Internet connection for npm package checks

## 🚀 Quick Start

### Installation

**Option A: Using Git (Recommended)**
```powershell
git clone https://github.com/FritzDerFred/-shai-hulud-powershell-beta-scanner.git
cd -shai-hulud-powershell-beta-scanner
.\shai-hulud-detector.ps1
```

**Option B: Download from GitHub**
1. Go to https://github.com/FritzDerFred/-shai-hulud-powershell-beta-scanner
2. Click the green "Code" button → "Download ZIP"
3. Extract the ZIP file to your desired location (e.g., `C:\Security\shai-hulud-scanner`)
4. Open PowerShell and navigate to the extracted directory:
   ```powershell
   cd "C:\Security\shai-hulud-scanner"
   .\shai-hulud-detector.ps1
   ```

The script will:
- ✅ Automatically request Administrator privileges
- ✅ Perform system pre-flight checks
- ✅ Guide you through interactive setup
- ✅ Generate a detailed security report

## 📖 Usage

### Interactive Mode (Recommended)

Simply run without parameters:

```powershell
.\shai-hulud-detector.ps1
```

The scanner will:
1. Check system prerequisites
2. Ask which directory to scan
3. Ask whether to enable Paranoid Mode
4. Show project analysis
5. Wait for confirmation before scanning

### Command-Line Mode

For automation or scripting:

```powershell
# Basic scan
.\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp"

# With Paranoid Mode (additional checks)
.\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp" -Paranoid
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Path` | No* | Directory to scan (prompted if not provided) |
| `-Paranoid` | No | Enable additional security checks (typosquatting, network patterns) |
| `-Parallelism` | No | Number of parallel threads (default: CPU count) |

\* *If not provided, interactive mode will prompt for path*

## 📊 What Gets Scanned

The scanner analyzes:

### Files
- `package.json` - Dependency analysis
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` - Lockfile verification
- `node_modules/` - Installed packages
- `.github/workflows/` - CI/CD pipeline files
- JavaScript/TypeScript files - Malware pattern detection
- Shell scripts - Destructive pattern detection

### Checks Performed
1. **Hash-based detection** - Known malicious file signatures
2. **Package version matching** - Compromised package versions
3. **Pattern matching** - Malware behavioral patterns
4. **Lockfile integrity** - Tampered dependency locks
5. **Workflow analysis** - Malicious GitHub Actions
6. **Content scanning** - Suspicious code patterns

## 📁 Report Output

After scanning, a detailed report is saved:

```
shai-hulud-report_YYYY-MM-DD_HH-mm-ss.txt
```

The report includes:
- ✅ **High Risk** findings - Confirmed malware/compromised packages
- ⚠️ **Medium Risk** findings - Suspicious patterns requiring review
- ℹ️ **Low Risk** findings - Informational (likely false positives)
- 📊 Summary statistics
- 🔍 Detailed file paths and contexts

### Report Location

Reports are saved in the scanned directory:
```
C:\Your\Project\shai-hulud-report_2025-01-27_15-30-00.txt
```

## 🛡️ Security Features

### Pre-Flight Checks

Before scanning, the tool verifies:
- PowerShell version compatibility
- Administrator privileges
- npm/Node.js installation
- Malware database availability
- Project structure validation

### Live Progress

Real-time status display:
```
[Scanning 247/1000] \path\to\current\file.js
[package.json 5/12] \path\to\package.json
```

### Auto-Elevation

The script automatically requests admin privileges if not already elevated.

## 🎨 Example Output

```
=============================================
        SYSTEM PRE-FLIGHT CHECK
=============================================

[✓] PowerShell Version: 5.1
[✓] Administrator Rights: ACTIVE
[✓] Malware Database: Found (1676 packages)

--- NPM/NODE.JS ENVIRONMENT ---

[✓] npm found: C:\Program Files\nodejs\npm.cmd
    Version: 10.2.4
[✓] Node.js found: C:\Program Files\nodejs\node.exe
    Version: v20.11.0

=============================================
✅ System is ready!
=============================================
```

## 🔍 Example Findings

```
🚨 HIGH RISK: Compromised package versions detected:
   - Package: chalk@5.6.1
     Found in: C:\Project\package.json
     [Context: Contains crypto theft malware]

⚠️  MEDIUM RISK: Suspicious content patterns:
   - Pattern: webhook.site reference
     Found in: C:\Project\suspicious.js
     [Manual review recommended]
```

## 🧪 Testing

The scanner includes a test suite in `test-cases/`:

```
test-cases/
├── infected-project/        # Simulated compromised project
├── chalk-debug-attack/      # September 2025 attack samples
├── november-2025-attack/    # November 2025 Bun attack
├── false-positive-project/  # Legitimate code patterns
└── ...
```

To test the scanner:
```powershell
.\shai-hulud-detector.ps1 -Path ".\test-cases"
```

## 📚 Attack Background

### Shai-Hulud Attack Campaign

A sophisticated, self-replicating supply chain attack targeting npm packages:

- **September 2025**: Initial wave compromising popular packages (chalk, debug, etc.)
- **Self-Replicating**: Malware propagates through package dependencies
- **Cryptocurrency Theft**: Wallet address replacement in browser environments
- **Credential Harvesting**: TruffleHog abuse for GitHub/AWS credentials
- **Persistent Backdoors**: GitHub Actions runners for long-term access

### References

- [StepSecurity: ctrl-tinycolor and 40+ npm packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Semgrep: Security Advisory - npm packages using secret scanning tools](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [JFrog: Shai-Hulud npm supply chain attack](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- [Wiz.io: Shai-Hulud npm supply chain attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Socket.dev: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)

## 🛠️ Troubleshooting

### Common Issues

**Script won't run / Execution Policy error:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Admin rights not working:**
- Right-click PowerShell → "Run as Administrator"
- Then navigate to the script and run it

**npm not found:**
- The scanner works without npm but has limited functionality
- Install Node.js from [nodejs.org](https://nodejs.org/)

**False positives:**
- Review Medium/Low risk findings carefully
- Legitimate security tools may trigger pattern matches
- Check file context before taking action

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection patterns
4. Submit a pull request

### Adding New Malware Signatures

Edit `compromised-packages.txt`:
```
# Format: package_name:version
malicious-package:1.2.3
another-bad-package:4.5.6
```

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## ⚠️ Disclaimer

**BETA SOFTWARE - NO WARRANTIES OR GUARANTEES**

This tool is provided **"AS IS"** for security research and defensive purposes only.

**The authors, contributors, and maintainers:**
- ❌ Assume **NO RESPONSIBILITY** for any misuse, damage, data loss, or security issues arising from the use of this tool
- ❌ Provide **NO WARRANTIES** of any kind, either express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement
- ❌ Make **NO GUARANTEES** regarding detection accuracy, completeness, or the absence of false positives/negatives
- ❌ Are **NOT LIABLE** for any claims, damages, or other liability arising from the use of this software

**Your responsibilities:**
- ✅ **Always verify findings manually** before taking any action
- ✅ **Test in a safe environment** before using on production systems
- ✅ **Backup your data** before scanning
- ✅ **Review the code** and understand what it does before running it
- ✅ **Use at your own risk** - You accept full responsibility for any consequences

This is a **BETA DRAFT** version under active development. Features may be incomplete, buggy, or change without notice.

# 🙏 **CREDITS & ATTRIBUTION**

---

## ⭐ **ORIGINAL WORK BY COBENIAN** ⭐

### **THIS IS A POWERSHELL PORT OF THE ORIGINAL BASH SCRIPT**

> # **[Original Author: Cobenian](https://github.com/Cobenian)**
>
> # **[Original Repository: shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)**
>
> **License:** MIT

---

### **🔴 IMPORTANT: ALL CREDIT GOES TO THE ORIGINAL AUTHOR 🔴**

**ALL** detection logic, malware signatures, and the `compromised-packages.txt` database originate from **[Cobenian's excellent work](https://github.com/Cobenian/shai-hulud-detect)**.

This PowerShell version is merely a port to bring the same security capabilities to Windows/PowerShell environments. **The original Bash script and research are 100% by Cobenian.**

---

### What This Port Adds

- ✅ Native Windows/PowerShell support
- ✅ Interactive mode with guided setup
- ✅ Automated admin privilege elevation
- ✅ Pre-flight system checks
- ✅ Live progress indicators
- ✅ Enhanced error handling for Windows paths

### Malware Database

The `compromised-packages.txt` file is maintained by [Cobenian](https://github.com/Cobenian/shai-hulud-detect) and includes:
- 1676+ confirmed compromised npm package versions
- Continuously updated with new discoveries
- Sourced from security advisories and research

**Please check the [original repository](https://github.com/Cobenian/shai-hulud-detect) for the latest database updates.**

### Additional Acknowledgments

- Security research teams at StepSecurity, JFrog, Wiz.io, Socket.dev, and Semgrep
- The npm security community
- All contributors who help maintain the compromised packages database

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/FritzDerFred/shai-hulud-detector/issues)
- **Security**: Report vulnerabilities via GitHub Security Advisories

---

**Stay Safe! 🛡️ Scan your projects regularly.**
