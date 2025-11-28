<#
.SYNOPSIS
    Shai-Hulud NPM Supply Chain Attack Detection Script

.DESCRIPTION
    Detects indicators of compromise from September 2025 and November 2025 npm attacks
    Includes detection for "Shai-Hulud: The Second Coming" (fake Bun runtime attack)

    ⚠️  CREDITS ⚠️
    This is a PowerShell port of the original Bash script by Cobenian.
    Original repository: https://github.com/Cobenian/shai-hulud-detect

    All detection logic, malware signatures, and the compromised-packages.txt
    database originate from Cobenian's work. This port brings the same
    security capabilities to Windows/PowerShell environments.

.PARAMETER Path
    Directory to scan for indicators of compromise

.PARAMETER Paranoid
    Enable additional security checks (typosquatting, network patterns)
    These are general security features, not specific to Shai-Hulud

.PARAMETER Parallelism
    Set the number of threads to use for parallelized steps

.EXAMPLE
    .\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp"

.EXAMPLE
    .\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp" -Paranoid

.NOTES
    Original Author: Cobenian (https://github.com/Cobenian/shai-hulud-detect)
    PowerShell Port: Community contribution
    License: MIT
    Version: 1.0 (PowerShell Port)

    Database: compromised-packages.txt is maintained by Cobenian
    Please check the original repository for updates.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Path = "",

    [Parameter(Mandatory = $false)]
    [switch]$Paranoid,

    [Parameter(Mandatory = $false)]
    [int]$Parallelism = [Environment]::ProcessorCount
)

#region Admin Elevation
# Check if running as Administrator, if not, relaunch with elevated privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires Administrator privileges. Relaunching with elevated permissions..." -ForegroundColor Yellow

    # Build command string with proper escaping for paths with spaces
    $escapedScript = $PSCommandPath -replace '"', '`"'

    # Start building command - only add -Path if it was provided
    $argString = "-NoExit -ExecutionPolicy Bypass -Command `"& '$escapedScript'"

    # Only add Path parameter if it was provided
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $escapedPath = $Path -replace '"', '`"'
        $argString += " -Path '$escapedPath'"
    }

    if ($Paranoid) {
        $argString += " -Paranoid"
    }
    if ($PSBoundParameters.ContainsKey('Parallelism')) {
        $argString += " -Parallelism $Parallelism"
    }

    $argString += "`""

    # Relaunch with admin privileges
    Start-Process powershell.exe -ArgumentList $argString -Verb RunAs
    exit
}

Write-Host "Running with Administrator privileges..." -ForegroundColor Green
#endregion

#region System Pre-Flight Check
# Check system prerequisites BEFORE asking for input
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "        SYSTEM PRE-FLIGHT CHECK" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Checking if system is ready..." -ForegroundColor Yellow
Write-Host ""

# Check 1: PowerShell Version
$psVersion = $PSVersionTable.PSVersion
$psVersionOk = $psVersion.Major -ge 5
if ($psVersionOk) {
    Write-Host "[✓] PowerShell Version: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Green
} else {
    Write-Host "[✗] PowerShell Version: $($psVersion.Major).$($psVersion.Minor) - TOO OLD!" -ForegroundColor Red
    Write-Host "    Required: PowerShell 5.0 or higher" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Check 2: Administrator Rights (should always be true here)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[✓] Administrator Rights: ACTIVE" -ForegroundColor Green
} else {
    Write-Host "[✗] Administrator Rights: MISSING (this should not happen!)" -ForegroundColor Red
}

# Check 3: Script Location
Write-Host "[✓] Script Directory: $PSScriptRoot" -ForegroundColor Green

# Check 4: Compromised Packages Database
$packagesFile = Join-Path $PSScriptRoot "compromised-packages.txt"
if (Test-Path $packagesFile) {
    Write-Host "[✓] Malware Database: Found" -ForegroundColor Green
    Write-Host "    File: $packagesFile" -ForegroundColor Gray
} else {
    Write-Host "[!] Malware Database: Not found" -ForegroundColor Yellow
    Write-Host "    Embedded list will be used (limited)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "--- NPM/NODE.JS ENVIRONMENT ---" -ForegroundColor Cyan
Write-Host ""

# Check 5: npm Installation
$npmAvailable = $false
try {
    $npmPath = (Get-Command npm -ErrorAction Stop).Source
    $npmVersion = (npm --version 2>$null)
    Write-Host "[✓] npm found: $npmPath" -ForegroundColor Green
    Write-Host "    Version: $npmVersion" -ForegroundColor Gray
    $npmAvailable = $true
} catch {
    Write-Host "[!] npm not found in system PATH" -ForegroundColor Yellow
    Write-Host "    Scanner works anyway (checks existing files)" -ForegroundColor Gray
}

# Check 6: Node.js Installation
$nodeAvailable = $false
try {
    $nodePath = (Get-Command node -ErrorAction Stop).Source
    $nodeVersion = (node --version 2>$null)
    Write-Host "[✓] Node.js found: $nodePath" -ForegroundColor Green
    Write-Host "    Version: $nodeVersion" -ForegroundColor Gray
    $nodeAvailable = $true
} catch {
    Write-Host "[!] Node.js not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
if ($psVersionOk -and $isAdmin) {
    Write-Host "✅ System is ready!" -ForegroundColor Green
} else {
    Write-Host "⚠️  System has problems - see above" -ForegroundColor Yellow
}
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $npmAvailable -and -not $nodeAvailable) {
    Write-Host "⚠️  WARNING: Neither npm nor Node.js found!" -ForegroundColor Yellow
    Write-Host "The scanner works but cannot perform npm-specific checks." -ForegroundColor Yellow
    Write-Host ""
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -notmatch "^[jJyY]") {
        Write-Host "Scan aborted." -ForegroundColor Red
        exit 0
    }
    Write-Host ""
}

Start-Sleep -Seconds 1
#endregion

#region Interactive Mode
# If no path was provided, enter interactive mode
if ([string]::IsNullOrWhiteSpace($Path)) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "   SHAI-HULUD NPM SUPPLY CHAIN DETECTOR" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This scanner checks Node.js/npm projects for:" -ForegroundColor Yellow
    Write-Host "  - Compromised npm packages (1676+ known versions)" -ForegroundColor White
    Write-Host "  - Malicious GitHub Actions Workflows" -ForegroundColor White
    Write-Host "  - Cryptocurrency Theft Malware" -ForegroundColor White
    Write-Host "  - Credential Harvesting Scripts" -ForegroundColor White
    Write-Host "  - November 2025 Bun Attack Patterns" -ForegroundColor White
    Write-Host ""
    Write-Host "EXAMPLES of scan paths:" -ForegroundColor Green
    Write-Host "  C:\Users\YourUsername\Documents\MyProject" -ForegroundColor Gray
    Write-Host "  C:\Users\YourUsername\Documents\GitHub" -ForegroundColor Gray
    Write-Host "  C:\Projects\NodeJS-App" -ForegroundColor Gray
    Write-Host ""
    Write-Host "WARNING: Do NOT scan the entire C:\ - this takes hours!" -ForegroundColor Red
    Write-Host ""

    # Ask for scan path
    do {
        $inputPath = Read-Host "Which folder do you want to scan? (Enter path)"

        # Clean up input: trim whitespace and remove quotes
        $inputPath = $inputPath.Trim()
        $inputPath = $inputPath.Trim('"', "'")

        if ([string]::IsNullOrWhiteSpace($inputPath)) {
            Write-Host "Error: Path cannot be empty!" -ForegroundColor Red
            $Path = $null
            continue
        }

        Write-Host "Checking path: $inputPath" -ForegroundColor Gray

        if (-not (Test-Path $inputPath -PathType Container)) {
            Write-Host "Error: Folder '$inputPath' does not exist!" -ForegroundColor Red
            Write-Host "Please enter a valid path." -ForegroundColor Yellow
            $Path = $null
        }
        else {
            # Path is valid
            $Path = $inputPath
        }
    } while ([string]::IsNullOrWhiteSpace($Path))

    Write-Host ""
    Write-Host "Selected path: $Path" -ForegroundColor Green
    Write-Host ""

    # Ask for paranoid mode
    Write-Host "Enable PARANOID MODE?" -ForegroundColor Yellow
    Write-Host "  YES = Additional checks (Typosquatting, Network Patterns)" -ForegroundColor White
    Write-Host "  NO  = Only Shai-Hulud specific checks (faster)" -ForegroundColor White
    Write-Host ""

    $paranoidChoice = Read-Host "Enable Paranoid Mode? (y/N)"

    if ($paranoidChoice -match "^[jJyY]") {
        $Paranoid = $true
        Write-Host "Paranoid Mode: ENABLED" -ForegroundColor Green
    }
    else {
        $Paranoid = $false
        Write-Host "Paranoid Mode: DISABLED" -ForegroundColor Gray
    }

}
#endregion

#region Project Scan Confirmation
# Show project details and ask for final confirmation
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "      PROJECT SCAN CONFIRMATION" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check: Scan Path
if ([string]::IsNullOrWhiteSpace($Path)) {
    Write-Host "[✗] Scan Path: NOT SPECIFIED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: No scan path available. This should not happen!" -ForegroundColor Red
    exit 1
} else {
    $pathExists = Test-Path $Path -PathType Container
    if ($pathExists) {
        Write-Host "[✓] Scan Path: $Path" -ForegroundColor Green

        # Show path info
        try {
            $pathInfo = Get-Item $Path
            Write-Host "    Full path: $($pathInfo.FullName)" -ForegroundColor Gray
        } catch {
            # Ignore errors
        }
    } else {
        Write-Host "[✗] Scan Path: DOES NOT EXIST" -ForegroundColor Red
        Write-Host "    Path: $Path" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Error: The specified path does not exist!" -ForegroundColor Red
        exit 1
    }
}

# Show scan settings
Write-Host "SCAN SETTINGS:" -ForegroundColor Cyan
if ($Paranoid) {
    Write-Host "  Paranoid Mode: ENABLED (extended checks)" -ForegroundColor Yellow
} else {
    Write-Host "  Paranoid Mode: DISABLED (standard checks)" -ForegroundColor Green
}

Write-Host ""
Write-Host "PROJECT ANALYSIS:" -ForegroundColor Cyan

if (-not [string]::IsNullOrWhiteSpace($Path)) {
    # Check for package.json
    $packageJsons = Get-ChildItem -Path $Path -Filter "package.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
    $packageJsonCount = ($packageJsons | Measure-Object).Count

    if ($packageJsonCount -gt 0) {
        Write-Host "[✓] package.json found: $packageJsonCount file(s)" -ForegroundColor Green
        Write-Host "    Info: package.json defines npm packages and scripts for your project" -ForegroundColor Gray

        # Show first few locations
        $packageJsons | Select-Object -First 3 | ForEach-Object {
            Write-Host "    - $($_.DirectoryName)" -ForegroundColor DarkGray
        }
        if ($packageJsonCount -gt 3) {
            Write-Host "    - ... and $($packageJsonCount - 3) more" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "[!] No package.json found" -ForegroundColor Yellow
        Write-Host "    Info: This folder apparently contains no Node.js/npm projects" -ForegroundColor Gray
    }

    # Check for node_modules
    $nodeModules = Get-ChildItem -Path $Path -Filter "node_modules" -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
    $nodeModulesCount = ($nodeModules | Measure-Object).Count

    if ($nodeModulesCount -gt 0) {
        Write-Host "[✓] node_modules folders found: $nodeModulesCount" -ForegroundColor Green
        Write-Host "    Info: node_modules contains all installed npm packages" -ForegroundColor Gray
        Write-Host "    This is where the scanner searches for compromised packages!" -ForegroundColor Yellow
    } else {
        Write-Host "[!] No node_modules folders found" -ForegroundColor Yellow
        Write-Host "    Info: Run 'npm install' to install packages" -ForegroundColor Gray
    }

    # Check for package-lock.json / yarn.lock / pnpm-lock.yaml
    $lockfiles = @()
    if (Get-ChildItem -Path $Path -Filter "package-lock.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $lockfiles += "package-lock.json (npm)"
    }
    if (Get-ChildItem -Path $Path -Filter "yarn.lock" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $lockfiles += "yarn.lock (Yarn)"
    }
    if (Get-ChildItem -Path $Path -Filter "pnpm-lock.yaml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $lockfiles += "pnpm-lock.yaml (pnpm)"
    }

    if ($lockfiles.Count -gt 0) {
        Write-Host "[✓] Lockfiles found: $($lockfiles -join ', ')" -ForegroundColor Green
        Write-Host "    Info: Lockfiles pin exact package versions" -ForegroundColor Gray
    } else {
        Write-Host "[!] No lockfiles found" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "             SCAN SUMMARY" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The scan will check for:" -ForegroundColor Yellow
Write-Host "  • 1676+ compromised npm packages" -ForegroundColor White
Write-Host "  • Malicious GitHub Actions Workflows" -ForegroundColor White
Write-Host "  • Cryptocurrency Theft Patterns" -ForegroundColor White
Write-Host "  • Credential Harvesting Scripts" -ForegroundColor White
Write-Host "  • Destructive Payloads" -ForegroundColor White
Write-Host "  • November 2025 Bun Attack Patterns" -ForegroundColor White

if ($Paranoid) {
    Write-Host "  • Typosquatting/Homoglyph Attacks (Paranoid)" -ForegroundColor Yellow
    Write-Host "  • Network Exfiltration Patterns (Paranoid)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Report will be saved in:" -ForegroundColor Yellow
Write-Host "  $Path\shai-hulud-report_[timestamp].txt" -ForegroundColor Gray
Write-Host ""

# Estimate scan time
Write-Host "Estimated scan duration:" -ForegroundColor Yellow
if ($Path -match "^C:\\$") {
    Write-Host "  ⚠️  WARNING: Entire C:\ - can take HOURS!" -ForegroundColor Red
} elseif ($Path -match "^C:\\(Program Files|Windows|Users$)") {
    Write-Host "  ⚠️  Large system folder - can take 30-60 minutes" -ForegroundColor Yellow
} else {
    Write-Host "  Typical project: 1-5 minutes" -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ready to start!" -ForegroundColor Green
Write-Host ""
$confirmation = Read-Host "Press ENTER to start or CTRL+C to cancel"

Write-Host ""
Write-Host "Starting scan..." -ForegroundColor Cyan
Write-Host ""
Start-Sleep -Seconds 1
#endregion

# Strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Global Variables

# Global temp directory for file-based storage
$script:TempDir = $null

# Global variables for risk tracking (used for exit codes)
$script:HighRisk = 0
$script:MediumRisk = 0

# Known malicious file hashes
$script:MaliciousHashList = @(
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b"
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee"
)

# Known compromised namespaces
$script:CompromisedNamespaces = @(
    "@crowdstrike"
    "@art-ws"
    "@ngx"
    "@ctrl"
    "@nativescript-community"
    "@ahmedhfarag"
    "@operato"
    "@teselagen"
    "@things-factory"
    "@hestjs"
    "@nstudio"
    "@basic-ui-components-stc"
    "@nexe"
    "@thangved"
    "@tnf-dev"
    "@ui-ux-gang"
    "@yoobic"
)

# Compromised packages array (loaded from file or fallback)
$script:CompromisedPackages = @()

#endregion

#region Color Output Functions

function Write-ColorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )
    $originalColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $ForegroundColor
    Write-Host $Message
    $Host.UI.RawUI.ForegroundColor = $originalColor
}

function Write-StatusRed { param([string]$Message) Write-ColorOutput -Message $Message -ForegroundColor Red }
function Write-StatusYellow { param([string]$Message) Write-ColorOutput -Message $Message -ForegroundColor Yellow }
function Write-StatusGreen { param([string]$Message) Write-ColorOutput -Message $Message -ForegroundColor Green }
function Write-StatusBlue { param([string]$Message) Write-ColorOutput -Message $Message -ForegroundColor Cyan }

#endregion

#region Temp Directory Management

function New-TempDirectory {
    <#
    .SYNOPSIS
        Create temporary directory for findings storage
    #>
    $tempBase = [System.IO.Path]::GetTempPath()
    $tempName = "shai-hulud-detect-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $script:TempDir = Join-Path $tempBase $tempName
    
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
    
    # Create findings files
    $findingsFiles = @(
        "workflow_files.txt"
        "malicious_hashes.txt"
        "compromised_found.txt"
        "suspicious_found.txt"
        "suspicious_content.txt"
        "crypto_patterns.txt"
        "git_branches.txt"
        "postinstall_hooks.txt"
        "trufflehog_activity.txt"
        "shai_hulud_repos.txt"
        "namespace_warnings.txt"
        "low_risk_findings.txt"
        "integrity_issues.txt"
        "typosquatting_warnings.txt"
        "network_exfiltration_warnings.txt"
        "lockfile_safe_versions.txt"
        "bun_setup_files.txt"
        "bun_environment_files.txt"
        "new_workflow_files.txt"
        "github_sha1hulud_runners.txt"
        "preinstall_bun_patterns.txt"
        "second_coming_repos.txt"
        "actions_secrets_files.txt"
        "discussion_workflows.txt"
        "github_runners.txt"
        "destructive_patterns.txt"
        "trufflehog_patterns.txt"
    )
    
    foreach ($file in $findingsFiles) {
        $filePath = Join-Path $script:TempDir $file
        New-Item -ItemType File -Path $filePath -Force | Out-Null
    }
}

function Remove-TempDirectory {
    <#
    .SYNOPSIS
        Clean up temporary directory on script exit
    #>
    if ($script:TempDir -and (Test-Path $script:TempDir)) {
        Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region Helper Functions

function Get-FileHash256 {
    <#
    .SYNOPSIS
        Get SHA256 hash of a file
    #>
    param([string]$FilePath)
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    }
    catch {
        return $null
    }
}

function Show-FilePreview {
    <#
    .SYNOPSIS
        Display file context for HIGH RISK findings only
    #>
    param(
        [string]$FilePath,
        [string]$Context
    )
    
    if ($Context -like "*HIGH RISK*") {
        Write-Host "   ┌─ File: $FilePath" -ForegroundColor Cyan
        Write-Host "   │  Context: $Context" -ForegroundColor Cyan
        Write-Host "   └─" -ForegroundColor Cyan
        Write-Host ""
    }
}

function Show-Progress {
    <#
    .SYNOPSIS
        Display real-time progress indicator
    #>
    param(
        [int]$Current,
        [int]$Total
    )
    
    $percent = 0
    if ($Total -gt 0) {
        $percent = [math]::Floor(($Current * 100) / $Total)
    }
    Write-Host "`r$Current / $Total checked ($percent %)" -NoNewline
}

function Get-FileContext {
    <#
    .SYNOPSIS
        Classify file context for risk assessment
    #>
    param([string]$FilePath)
    
    if ($FilePath -match [regex]::Escape("\node_modules\") -or $FilePath -match "/node_modules/") {
        return "node_modules"
    }
    
    if ($FilePath -match "\.(md|txt|rst)$") {
        return "documentation"
    }
    
    if ($FilePath -match "\.d\.ts$") {
        return "type_definitions"
    }
    
    if ($FilePath -match [regex]::Escape("\dist\") -or $FilePath -match [regex]::Escape("\build\") -or 
        $FilePath -match [regex]::Escape("\public\") -or $FilePath -match "/dist/" -or 
        $FilePath -match "/build/" -or $FilePath -match "/public/") {
        return "build_output"
    }
    
    $fileName = Split-Path -Leaf $FilePath
    if ($fileName -match "config" -or $fileName -match "\.config\.") {
        return "configuration"
    }
    
    return "source_code"
}

function Test-LegitimatePattern {
    <#
    .SYNOPSIS
        Identify legitimate framework/build tool patterns
    #>
    param(
        [string]$FilePath,
        [string]$ContentSample
    )
    
    # Vue.js development patterns
    if ($ContentSample -match "process\.env\.NODE_ENV" -and $ContentSample -match "production") {
        return $true
    }
    
    # Common framework patterns
    if ($ContentSample -match "createApp" -or $ContentSample -match "Vue") {
        return $true
    }
    
    # Package manager and build tool patterns
    if ($ContentSample -match "webpack" -or $ContentSample -match "vite" -or $ContentSample -match "rollup") {
        return $true
    }
    
    return $false
}

function Add-Finding {
    <#
    .SYNOPSIS
        Add a finding to a findings file
    #>
    param(
        [string]$FileName,
        [string]$Content
    )
    
    $filePath = Join-Path $script:TempDir $FileName
    Add-Content -Path $filePath -Value $Content -Encoding UTF8
}

function Get-Findings {
    <#
    .SYNOPSIS
        Get findings from a findings file
    #>
    param([string]$FileName)

    $filePath = Join-Path $script:TempDir $FileName
    if (Test-Path $filePath) {
        $content = Get-Content -Path $filePath -ErrorAction SilentlyContinue
        # Force return as array to ensure .Count works in strict mode
        return @($content | Where-Object { $_ -ne "" })
    }
    return @()
}

function Test-FindingsExist {
    <#
    .SYNOPSIS
        Check if findings file has content
    #>
    param([string]$FileName)
    
    $filePath = Join-Path $script:TempDir $FileName
    if (Test-Path $filePath) {
        $content = Get-Content -Path $filePath -ErrorAction SilentlyContinue
        return ($content | Where-Object { $_ -ne "" }).Count -gt 0
    }
    return $false
}

#endregion

#region Package Loading

function Import-CompromisedPackages {
    <#
    .SYNOPSIS
        Load compromised package database from external file or fallback list
    #>
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $scriptDir) {
        $scriptDir = $PWD.Path
    }
    $packagesFile = Join-Path $scriptDir "compromised-packages.txt"
    
    $script:CompromisedPackages = @()
    
    if (Test-Path $packagesFile) {
        $lines = Get-Content -Path $packagesFile -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            # Trim potential Windows carriage returns
            $line = $line.Trim()
            
            # Skip comments and empty lines
            if ($line -match "^\s*#" -or [string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            
            # Add valid package:version lines to array
            if ($line -match "^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+") {
                $script:CompromisedPackages += $line
            }
        }
        
        Write-StatusBlue "📦 Loaded $($script:CompromisedPackages.Count) compromised packages from $packagesFile"
    }
    else {
        # Fallback to embedded list if file not found
        Write-StatusYellow "⚠️  Warning: $packagesFile not found, using embedded package list"
        $script:CompromisedPackages = @(
            "@ctrl/tinycolor:4.1.0"
            "@ctrl/tinycolor:4.1.1"
            "@ctrl/tinycolor:4.1.2"
            "@ctrl/deluge:1.2.0"
            "angulartics2:14.1.2"
            "koa2-swagger-ui:5.11.1"
            "koa2-swagger-ui:5.11.2"
        )
    }
}

#endregion

#region Semver Functions

function ConvertTo-SemverParts {
    <#
    .SYNOPSIS
        Parse semantic version string into components
    #>
    param([string]$Version)
    
    $result = @{
        Major = 0
        Minor = 0
        Patch = 0
        Special = ""
    }
    
    if ($Version -match "^(\d+)\.(\d+)\.(\d+)(.*)$") {
        $result.Major = [int]$Matches[1]
        $result.Minor = [int]$Matches[2]
        $result.Patch = [int]$Matches[3]
        $result.Special = $Matches[4]
    }
    
    return $result
}

function Test-SemverMatch {
    <#
    .SYNOPSIS
        Check if version matches semver pattern
    #>
    param(
        [string]$TestSubject,
        [string]$TestPattern
    )
    
    # Always matches
    if ($TestPattern -eq "*") {
        return $true
    }
    
    # Destructure subject
    $subject = ConvertTo-SemverParts -Version $TestSubject
    
    # Handle multi-variant patterns (split by ||)
    $patterns = $TestPattern -split "\|\|"
    
    foreach ($patternRaw in $patterns) {
        $pattern = $patternRaw.Trim()
        
        # Always matches
        if ($pattern -eq "*") {
            return $true
        }
        
        if ($pattern.StartsWith("^")) {
            # Major must match
            $patternParts = ConvertTo-SemverParts -Version ($pattern.Substring(1))
            
            if ($subject.Major -ne $patternParts.Major) { continue }
            if ($subject.Minor -lt $patternParts.Minor) { continue }
            if ($subject.Minor -eq $patternParts.Minor -and $subject.Patch -lt $patternParts.Patch) { continue }
            
            return $true
        }
        elseif ($pattern.StartsWith("~")) {
            # Major+minor must match
            $patternParts = ConvertTo-SemverParts -Version ($pattern.Substring(1))
            
            if ($subject.Major -ne $patternParts.Major) { continue }
            if ($subject.Minor -ne $patternParts.Minor) { continue }
            if ($subject.Patch -lt $patternParts.Patch) { continue }
            
            return $true
        }
        elseif ($pattern -match "x") {
            # Wildcard pattern (4.x, 1.2.x, etc.)
            $patternParts = $pattern -split "\."
            $subjectParts = $TestSubject -split "\."
            
            $match = $true
            for ($i = 0; $i -lt [Math]::Min($patternParts.Count, $subjectParts.Count); $i++) {
                if ($patternParts[$i] -eq "x") { continue }
                
                $patternNum = $patternParts[$i] -replace "[^0-9].*", ''
                $subjectNum = $subjectParts[$i] -replace "[^0-9].*", ''
                
                if ($patternNum -ne $subjectNum) {
                    $match = $false
                    break
                }
            }
            
            if ($match) { return $true }
        }
        else {
            # Exact match
            $patternParts = ConvertTo-SemverParts -Version $pattern
            
            if ($subject.Major -ne $patternParts.Major) { continue }
            if ($subject.Minor -ne $patternParts.Minor) { continue }
            if ($subject.Patch -ne $patternParts.Patch) { continue }
            if ($subject.Special -ne $patternParts.Special) { continue }
            
            return $true
        }
    }
    
    return $false
}

#endregion

#region Lockfile Functions

function Get-LockfileVersion {
    <#
    .SYNOPSIS
        Extract actual installed version from lockfile for a specific package
    #>
    param(
        [string]$PackageName,
        [string]$PackageDir,
        [string]$ScanBoundary
    )
    
    $currentDir = $PackageDir
    
    while ($currentDir -and $currentDir -ne [System.IO.Path]::GetPathRoot($currentDir)) {
        # Security: Don't search above the original scan directory boundary
        if (-not $currentDir.StartsWith($ScanBoundary)) {
            break
        }
        
        # Check for package-lock.json
        $lockfilePath = Join-Path $currentDir "package-lock.json"
        if (Test-Path $lockfilePath) {
            try {
                $lockfileContent = Get-Content -Path $lockfilePath -Raw -ErrorAction Stop
                $lockfile = $lockfileContent | ConvertFrom-Json -ErrorAction Stop
                
                # Check packages.node_modules/<packagename> structure
                $nodeModulesPath = "node_modules/$PackageName"
                if ($lockfile.packages -and $lockfile.packages.PSObject.Properties[$nodeModulesPath]) {
                    $version = $lockfile.packages.$nodeModulesPath.version
                    if ($version) { return $version }
                }
                
                # Check dependencies structure (older format)
                if ($lockfile.dependencies -and $lockfile.dependencies.PSObject.Properties[$PackageName]) {
                    $version = $lockfile.dependencies.$PackageName.version
                    if ($version) { return $version }
                }
            }
            catch {
                # JSON parsing failed, continue searching
            }
        }
        
        # Check for yarn.lock
        $yarnLockPath = Join-Path $currentDir "yarn.lock"
        if (Test-Path $yarnLockPath) {
            try {
                $content = Get-Content -Path $yarnLockPath -Raw -ErrorAction Stop
                if ($content -match "$([regex]::Escape($PackageName))@[^:]+:\s*\n\s*version\s+`"([^`"]+)`"") {
                    return $Matches[1]
                }
            }
            catch {
                # Continue searching
            }
        }
        
        # Check for pnpm-lock.yaml
        $pnpmLockPath = Join-Path $currentDir "pnpm-lock.yaml"
        if (Test-Path $pnpmLockPath) {
            try {
                $content = Get-Content -Path $pnpmLockPath -Raw -ErrorAction Stop
                # Simple regex extraction for pnpm-lock.yaml
                if ($content -match "'?$([regex]::Escape($PackageName))@([0-9]+\.[0-9]+\.[0-9]+[^']*)'?:") {
                    return $Matches[1]
                }
            }
            catch {
                # Continue searching
            }
        }
        
        # Move to parent directory
        $currentDir = Split-Path -Parent $currentDir
    }
    
    return $null
}

#endregion

#region Detection Functions

function Test-WorkflowFiles {
    <#
    .SYNOPSIS
        Detect malicious shai-hulud-workflow.yml files
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for malicious workflow files..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Filter "shai-hulud-workflow.yml" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -FileName "workflow_files.txt" -Content $_.FullName
    }
}

function Test-BunAttackFiles {
    <#
    .SYNOPSIS
        Detect November 2025 "Shai-Hulud: The Second Coming" Bun attack files
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for November 2025 Bun attack files..."
    
    # Known malicious file hashes from Koi.ai incident report
    $setupBunHashes = @(
        "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
    )
    
    $bunEnvironmentHashes = @(
        "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
        "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
        "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
    )
    
    # Look for setup_bun.js files
    Get-ChildItem -Path $ScanDir -Recurse -Filter "setup_bun.js" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -FileName "bun_setup_files.txt" -Content $_.FullName
        
        $fileHash = Get-FileHash256 -FilePath $_.FullName
        if ($fileHash -and $setupBunHashes -contains $fileHash) {
            Add-Finding -FileName "malicious_hashes.txt" -Content "$($_.FullName):SHA256=$fileHash (CONFIRMED MALICIOUS - Koi.ai IOC)"
        }
    }
    
    # Look for bun_environment.js files
    Get-ChildItem -Path $ScanDir -Recurse -Filter "bun_environment.js" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -FileName "bun_environment_files.txt" -Content $_.FullName
        
        $fileHash = Get-FileHash256 -FilePath $_.FullName
        if ($fileHash -and $bunEnvironmentHashes -contains $fileHash) {
            Add-Finding -FileName "malicious_hashes.txt" -Content "$($_.FullName):SHA256=$fileHash (CONFIRMED MALICIOUS - Koi.ai IOC)"
        }
    }
}

function Test-NewWorkflowPatterns {
    <#
    .SYNOPSIS
        Detect November 2025 new workflow file patterns and actionsSecrets.json
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for new workflow patterns..."
    
    # Look for formatter_*.yml workflow files
    Get-ChildItem -Path $ScanDir -Recurse -Filter "formatter_*.yml" -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.DirectoryName -match "\.github[\\/]workflows" } | ForEach-Object {
            Add-Finding -FileName "new_workflow_files.txt" -Content $_.FullName
        }
    
    # Look for actionsSecrets.json files
    Get-ChildItem -Path $ScanDir -Recurse -Filter "actionsSecrets.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -FileName "actions_secrets_files.txt" -Content $_.FullName
    }
}

function Test-DiscussionWorkflows {
    <#
    .SYNOPSIS
        Detect malicious GitHub Actions workflows with discussion triggers
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for malicious discussion workflows..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.yml", "*.yaml" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "\.github[\\/]workflows" } | ForEach-Object {
            $filePath = $_.FullName
            try {
                $content = Get-Content -Path $filePath -Raw -ErrorAction Stop
                
                # Check for discussion-based triggers
                if ($content -match "on:.*discussion" -or $content -match "on:\s*discussion") {
                    Add-Finding -FileName "discussion_workflows.txt" -Content "$filePath`:Discussion trigger detected"
                }
                
                # Check for self-hosted runners combined with dynamic payload execution
                if ($content -match "runs-on:.*self-hosted") {
                    if ($content -match '\$\{\{\s*github\.event\..*\.body\s*\}\}') {
                        Add-Finding -FileName "discussion_workflows.txt" -Content "$filePath`:Self-hosted runner with dynamic payload execution"
                    }
                }
                
                # Check for specific discussion.yaml filename
                $fileName = Split-Path -Leaf $filePath
                if ($fileName -eq "discussion.yaml" -or $fileName -eq "discussion.yml") {
                    Add-Finding -FileName "discussion_workflows.txt" -Content "$filePath`:Suspicious discussion workflow filename"
                }
            }
            catch {
                # Skip files that can't be read
            }
        }
}

function Test-GitHubRunners {
    <#
    .SYNOPSIS
        Detect self-hosted GitHub Actions runners installed by malware
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for malicious GitHub Actions runners..."
    
    $runnerPatterns = @(
        ".dev-env"
        "actions-runner"
        ".runner"
        "_work"
    )
    
    foreach ($pattern in $runnerPatterns) {
        Get-ChildItem -Path $ScanDir -Recurse -Directory -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            $dir = $_.FullName
            
            # Check for runner configuration files
            if ((Test-Path (Join-Path $dir ".runner")) -or 
                (Test-Path (Join-Path $dir ".credentials")) -or 
                (Test-Path (Join-Path $dir "config.sh"))) {
                Add-Finding -FileName "github_runners.txt" -Content "$dir`:Runner configuration files found"
            }
            
            # Check for runner binaries
            if ((Test-Path (Join-Path $dir "Runner.Worker")) -or 
                (Test-Path (Join-Path $dir "run.sh")) -or 
                (Test-Path (Join-Path $dir "run.cmd"))) {
                Add-Finding -FileName "github_runners.txt" -Content "$dir`:Runner executable files found"
            }
            
            # Check for .dev-env specifically
            if ($_.Name -eq ".dev-env") {
                Add-Finding -FileName "github_runners.txt" -Content "$dir`:Suspicious .dev-env directory (matches Koi.ai report)"
            }
        }
    }
    
    # Also check user home directory specifically for ~/.dev-env
    $homeDevEnv = Join-Path $env:USERPROFILE ".dev-env"
    if (Test-Path $homeDevEnv) {
        Add-Finding -FileName "github_runners.txt" -Content "$homeDevEnv`:Malicious runner directory in home folder (Koi.ai IOC)"
    }
}

function Test-DestructivePatterns {
    <#
    .SYNOPSIS
        Detect destructive patterns that can cause data loss
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for destructive payload patterns..."
    
    $destructivePatterns = @(
        'rm -rf \$HOME'
        'rm -rf ~'
        'del /s /q'
        'Remove-Item -Recurse'
        'fs\.unlinkSync'
        'fs\.rmSync.*recursive'
        'rimraf'
        'find.*-delete'
        'find \$HOME.*-exec rm'
        'find ~.*-exec rm'
        '\$HOME/\*'
        '~/\*'
        'if.*credential.*fail.*rm'
        'if.*token.*not.*found.*delete'
        'if.*github.*auth.*fail.*rm'
        'catch.*rm -rf'
        'error.*delete.*home'
    )
    
    $extensions = @("*.js", "*.sh", "*.ps1", "*.py", "*.bat", "*.cmd")
    
    foreach ($ext in $extensions) {
        Get-ChildItem -Path $ScanDir -Recurse -Filter $ext -File -ErrorAction SilentlyContinue | 
            Select-Object -First 100 | ForEach-Object {
                try {
                    $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
                    foreach ($pattern in $destructivePatterns) {
                        if ($content -match $pattern) {
                            Add-Finding -FileName "destructive_patterns.txt" -Content "$($_.FullName):Destructive pattern detected: $pattern"
                        }
                    }
                }
                catch {
                    # Skip files that can't be read
                }
            }
    }
}

function Test-PreinstallBunPatterns {
    <#
    .SYNOPSIS
        Detect fake Bun runtime preinstall patterns in package.json files
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for fake Bun preinstall patterns..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Filter "package.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            if ($content -match '"preinstall"\s*:\s*"node setup_bun\.js"') {
                Add-Finding -FileName "preinstall_bun_patterns.txt" -Content $_.FullName
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-GitHubActionsRunner {
    <#
    .SYNOPSIS
        Detect SHA1HULUD GitHub Actions runners in workflow files
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for SHA1HULUD GitHub Actions runners..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.yml", "*.yaml" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            if ($content -match "SHA1HULUD") {
                Add-Finding -FileName "github_sha1hulud_runners.txt" -Content $_.FullName
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-SecondComingRepos {
    <#
    .SYNOPSIS
        Detect repository descriptions with "Sha1-Hulud: The Second Coming" pattern
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for 'Second Coming' repository descriptions..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue | ForEach-Object {
        $repoDir = Split-Path -Parent $_.FullName
        $configPath = Join-Path $_.FullName "config"
        
        if (Test-Path $configPath) {
            try {
                $content = Get-Content -Path $configPath -Raw -ErrorAction Stop
                if ($content -match "Sha1-Hulud: The Second Coming") {
                    Add-Finding -FileName "second_coming_repos.txt" -Content $repoDir
                }
            }
            catch {
                # Skip files that can't be read
            }
        }
    }
}

function Test-FileHashes {
    <#
    .SYNOPSIS
        Scan files and compare SHA256 hashes against known malicious hash list
    #>
    param([string]$ScanDir)

    $files = @(Get-ChildItem -Path $ScanDir -Recurse -Include "*.js", "*.ts", "*.json" -File -ErrorAction SilentlyContinue)
    $filesCount = $files.Count

    Write-StatusBlue "🔍 Checking $filesCount files for known malicious content..."
    
    $filesChecked = 0

    foreach ($file in $files) {
        # Show current file being scanned
        $relativePath = $file.FullName.Replace($ScanDir, "").TrimStart('\', '/')
        if ($relativePath.Length -gt 80) {
            $relativePath = "..." + $relativePath.Substring($relativePath.Length - 77)
        }
        Write-Host "`r[Scanning $filesChecked/$filesCount] $relativePath" -NoNewline -ForegroundColor DarkGray

        $fileHash = Get-FileHash256 -FilePath $file.FullName

        if ($fileHash -and $script:MaliciousHashList -contains $fileHash) {
            Add-Finding -FileName "malicious_hashes.txt" -Content "$($file.FullName):$fileHash"
        }

        $filesChecked++
    }
    
    Write-Host "`r" -NoNewline
    Write-Host (" " * 50) -NoNewline
    Write-Host "`r" -NoNewline
}

function Test-Packages {
    <#
    .SYNOPSIS
        Scan package.json files for compromised packages and suspicious namespaces
    #>
    param([string]$ScanDir)

    $packageFiles = @(Get-ChildItem -Path $ScanDir -Recurse -Filter "package.json" -File -ErrorAction SilentlyContinue)
    $filesCount = $packageFiles.Count

    Write-StatusBlue "🔍 Checking $filesCount package.json files for compromised packages..."
    
    $filesChecked = 0

    foreach ($packageFile in $packageFiles) {
        # Show current file being scanned
        $relativePath = $packageFile.FullName.Replace($ScanDir, "").TrimStart('\', '/')
        if ($relativePath.Length -gt 70) {
            $relativePath = "..." + $relativePath.Substring($relativePath.Length - 67)
        }
        Write-Host "`r[package.json $filesChecked/$filesCount] $relativePath" -NoNewline -ForegroundColor DarkGray

        try {
            $content = Get-Content -Path $packageFile.FullName -Raw -ErrorAction Stop
            $json = $content | ConvertFrom-Json -ErrorAction Stop
            
            # Collect all dependencies
            $allDeps = @{}
            
            @("dependencies", "devDependencies", "peerDependencies", "optionalDependencies") | ForEach-Object {
                $depType = $_
                if ($json.PSObject.Properties[$depType]) {
                    $json.$depType.PSObject.Properties | ForEach-Object {
                        $allDeps[$_.Name] = $_.Value
                    }
                }
            }
            
            # Check each dependency against compromised packages
            foreach ($dep in $allDeps.GetEnumerator()) {
                $packageName = $dep.Key
                $packageVersion = $dep.Value -replace '"', ''
                
                foreach ($maliciousInfo in $script:CompromisedPackages) {
                    $parts = $maliciousInfo -split ':'
                    $maliciousName = $parts[0]
                    $maliciousVersion = $parts[1]
                    
                    if ($packageName -ne $maliciousName) { continue }
                    
                    if ($packageVersion -eq $maliciousVersion) {
                        # Exact match, certainly compromised
                        Add-Finding -FileName "compromised_found.txt" -Content "$($packageFile.FullName):$packageName@$packageVersion"
                    }
                    elseif (Test-SemverMatch -TestSubject $maliciousVersion -TestPattern $packageVersion) {
                        # Semver pattern match - check lockfile for actual installed version
                        $packageDir = Split-Path -Parent $packageFile.FullName
                        $actualVersion = Get-LockfileVersion -PackageName $packageName -PackageDir $packageDir -ScanBoundary $ScanDir
                        
                        if ($actualVersion) {
                            if ($actualVersion -eq $maliciousVersion) {
                                Add-Finding -FileName "compromised_found.txt" -Content "$($packageFile.FullName):$packageName@$actualVersion"
                            }
                            else {
                                Add-Finding -FileName "lockfile_safe_versions.txt" -Content "$($packageFile.FullName):$packageName@$packageVersion (locked to $actualVersion - safe)"
                            }
                        }
                        else {
                            Add-Finding -FileName "suspicious_found.txt" -Content "$($packageFile.FullName):$packageName@$packageVersion"
                        }
                    }
                }
            }
            
            # Check for suspicious namespaces
            foreach ($namespace in $script:CompromisedNamespaces) {
                if ($content -match [regex]::Escape('"' + $namespace + '/')) {
                    Add-Finding -FileName "namespace_warnings.txt" -Content "$($packageFile.FullName):Contains packages from compromised namespace: $namespace"
                }
            }
        }
        catch {
            # Skip files that can't be parsed
        }

        $filesChecked++
    }
    
    Write-Host "`r" -NoNewline
    Write-Host (" " * 50) -NoNewline
    Write-Host "`r" -NoNewline
}

function Test-PostinstallHooks {
    <#
    .SYNOPSIS
        Detect suspicious postinstall scripts
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for suspicious postinstall hooks..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Filter "package.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            
            if ($content -match '"postinstall"') {
                # Extract postinstall command
                if ($content -match '"postinstall"\s*:\s*"([^"]*)"') {
                    $postinstallCmd = $Matches[1]
                    
                    # Check for suspicious patterns
                    if ($postinstallCmd -match "curl" -or 
                        $postinstallCmd -match "wget" -or 
                        $postinstallCmd -match "node -e" -or 
                        $postinstallCmd -match "eval") {
                        Add-Finding -FileName "postinstall_hooks.txt" -Content "$($_.FullName):Suspicious postinstall: $postinstallCmd"
                    }
                }
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-SuspiciousContent {
    <#
    .SYNOPSIS
        Search for suspicious content patterns
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for suspicious content patterns..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.js", "*.ts", "*.json", "*.yml", "*.yaml" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            
            if ($content -match "webhook\.site") {
                Add-Finding -FileName "suspicious_content.txt" -Content "$($_.FullName):webhook.site reference"
            }
            
            if ($content -match "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7") {
                Add-Finding -FileName "suspicious_content.txt" -Content "$($_.FullName):malicious webhook endpoint"
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-CryptoTheftPatterns {
    <#
    .SYNOPSIS
        Detect cryptocurrency theft patterns from the Chalk/Debug attack
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for cryptocurrency theft patterns..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.js", "*.ts", "*.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            $filePath = $_.FullName
            
            # Check for wallet address replacement patterns
            if ($content -match "0x[a-fA-F0-9]{40}") {
                if ($content -match "ethereum|wallet|address|crypto") {
                    Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:Ethereum wallet address patterns detected"
                }
            }
            
            # Check for XMLHttpRequest hijacking with context-aware detection
            if ($content -match "XMLHttpRequest\.prototype\.send") {
                $context = Get-FileContext -FilePath $filePath
                
                if ($filePath -match "react-native[\\/]Libraries[\\/]Network" -or $filePath -match "next[\\/]dist[\\/]compiled") {
                    if ($content -match "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help") {
                        Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK"
                    }
                    else {
                        Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:XMLHttpRequest prototype modification detected in framework code - LOW RISK"
                    }
                }
                else {
                    if ($content -match "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help") {
                        Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK"
                    }
                    else {
                        Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:XMLHttpRequest prototype modification detected - MEDIUM RISK"
                    }
                }
            }
            
            # Check for specific malicious functions
            if ($content -match "checkethereumw|runmask|newdlocal|_0x19ca67") {
                Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:Known crypto theft function names detected"
            }
            
            # Check for known attacker wallets
            if ($content -match "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67") {
                Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:Known attacker wallet address detected - HIGH RISK"
            }
            
            # Check for npmjs.help phishing domain
            if ($content -match "npmjs\.help") {
                Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:Phishing domain npmjs.help detected"
            }
            
            # Check for javascript obfuscation patterns
            if ($content -match "javascript-obfuscator") {
                Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:JavaScript obfuscation detected"
            }
            
            # Check for cryptocurrency address regex patterns
            if ($content -match "ethereum.*0x\[a-fA-F0-9\]|bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]") {
                Add-Finding -FileName "crypto_patterns.txt" -Content "$filePath`:Cryptocurrency regex patterns detected"
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-GitBranches {
    <#
    .SYNOPSIS
        Search for suspicious git branches containing "shai-hulud"
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for suspicious git branches..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue | ForEach-Object {
        $repoDir = Split-Path -Parent $_.FullName
        $refsHeadsPath = Join-Path $_.FullName "refs\heads"
        
        if (Test-Path $refsHeadsPath) {
            Get-ChildItem -Path $refsHeadsPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "shai-hulud" } | ForEach-Object {
                    try {
                        $commitHash = Get-Content -Path $_.FullName -ErrorAction Stop
                        $shortHash = $commitHash.Substring(0, [Math]::Min(8, $commitHash.Length))
                        Add-Finding -FileName "git_branches.txt" -Content "$repoDir`:Branch '$($_.Name)' (commit: $shortHash...)"
                    }
                    catch {
                        Add-Finding -FileName "git_branches.txt" -Content "$repoDir`:Branch '$($_.Name)'"
                    }
                }
        }
    }
}

function Test-TrufflehogActivity {
    <#
    .SYNOPSIS
        Detect Trufflehog secret scanning activity
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for Trufflehog activity and secret scanning..."
    
    # Look for trufflehog binary files
    Get-ChildItem -Path $ScanDir -Recurse -Filter "*trufflehog*" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -FileName "trufflehog_activity.txt" -Content "$($_.FullName):HIGH:Trufflehog binary found"
    }
    
    # Look for potential trufflehog activity in files
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.js", "*.py", "*.sh", "*.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            $filePath = $_.FullName
            $context = Get-FileContext -FilePath $filePath
            $contentSample = $content.Substring(0, [Math]::Min(2000, $content.Length))
            
            # Check for explicit trufflehog references
            if ($content -match "trufflehog|TruffleHog") {
                switch ($context) {
                    "documentation" { 
                        # Documentation mentioning trufflehog is usually legitimate
                    }
                    { $_ -in @("node_modules", "type_definitions", "build_output") } {
                        Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:MEDIUM:Contains trufflehog references in $context"
                    }
                    default {
                        if ($contentSample -match "subprocess" -and $contentSample -match "curl") {
                            Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:Suspicious trufflehog execution pattern"
                        }
                        else {
                            Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:MEDIUM:Contains trufflehog references in source code"
                        }
                    }
                }
            }
            
            # Check for credential scanning combined with exfiltration
            if ($content -match "AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN") {
                switch ($context) {
                    { $_ -in @("type_definitions", "documentation") } {
                        # Normal
                    }
                    "node_modules" {
                        Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:LOW:Credential patterns in node_modules"
                    }
                    "configuration" {
                        if (-not ($contentSample -match "DefinePlugin" -or $contentSample -match "webpack")) {
                            Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:MEDIUM:Credential patterns in configuration"
                        }
                    }
                    default {
                        if ($contentSample -match "webhook\.site" -or $contentSample -match "curl" -or $contentSample -match "https\.request") {
                            Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:Credential patterns with potential exfiltration"
                        }
                        else {
                            Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:MEDIUM:Contains credential scanning patterns"
                        }
                    }
                }
            }
            
            # November 2025 specific TruffleHog patterns
            if ($content -match "TruffleHog.*scan.*credential|download.*trufflehog|trufflehog.*env|trufflehog.*AWS|trufflehog.*NPM_TOKEN") {
                if ($contentSample -match "download" -and $contentSample -match "trufflehog" -and $contentSample -match "scan") {
                    Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:November 2025 pattern - Automated TruffleHog download and credential scanning"
                }
                elseif ($contentSample -match "GitHub Action" -and $contentSample -match "trufflehog") {
                    Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:November 2025 pattern - TruffleHog in GitHub Actions for credential theft"
                }
                elseif ($contentSample -match "environment" -and $contentSample -match "token" -and $contentSample -match "trufflehog") {
                    Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:November 2025 pattern - TruffleHog environment token harvesting"
                }
                else {
                    Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:MEDIUM:Potential November 2025 TruffleHog attack pattern"
                }
            }
            
            # Check for specific command execution patterns
            if ($content -match "curl.*trufflehog|wget.*trufflehog|bunExecutable.*trufflehog") {
                Add-Finding -FileName "trufflehog_activity.txt" -Content "$filePath`:HIGH:November 2025 pattern - Dynamic TruffleHog download via curl/wget/Bun"
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-ShaiHuludRepos {
    <#
    .SYNOPSIS
        Detect Shai-Hulud worm repositories and malicious migration patterns
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking for Shai-Hulud repositories and migration patterns..."
    
    Get-ChildItem -Path $ScanDir -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue | ForEach-Object {
        $repoDir = Split-Path -Parent $_.FullName
        $repoName = Split-Path -Leaf $repoDir
        
        # Check repository name
        if ($repoName -match "shai-hulud|Shai-Hulud") {
            Add-Finding -FileName "shai_hulud_repos.txt" -Content "$repoDir`:Repository name contains 'Shai-Hulud'"
        }
        
        # Check for migration pattern
        if ($repoName -match "-migration") {
            Add-Finding -FileName "shai_hulud_repos.txt" -Content "$repoDir`:Repository name contains migration pattern"
        }
        
        # Check git config
        $configPath = Join-Path $_.FullName "config"
        if (Test-Path $configPath) {
            try {
                $content = Get-Content -Path $configPath -Raw -ErrorAction Stop
                if ($content -match "shai-hulud|Shai-Hulud") {
                    Add-Finding -FileName "shai_hulud_repos.txt" -Content "$repoDir`:Git remote contains 'Shai-Hulud'"
                }
            }
            catch { }
        }
        
        # Check for double base64-encoded data.json
        $dataJsonPath = Join-Path $repoDir "data.json"
        if (Test-Path $dataJsonPath) {
            try {
                $content = Get-Content -Path $dataJsonPath -Raw -ErrorAction Stop | Select-Object -First 5
                if ($content -match "eyJ" -and $content -match "==") {
                    Add-Finding -FileName "shai_hulud_repos.txt" -Content "$repoDir`:Contains suspicious data.json (possible base64-encoded credentials)"
                }
            }
            catch { }
        }
    }
}

function Test-PackageIntegrity {
    <#
    .SYNOPSIS
        Verify package lock files for compromised packages
    #>
    param([string]$ScanDir)
    
    Write-StatusBlue "🔍 Checking package lock files for integrity issues..."
    
    $lockFiles = Get-ChildItem -Path $ScanDir -Recurse -Include "package-lock.json", "yarn.lock", "pnpm-lock.yaml" -File -ErrorAction SilentlyContinue
    
    foreach ($lockfile in $lockFiles) {
        try {
            $content = Get-Content -Path $lockfile.FullName -Raw -ErrorAction Stop
            
            foreach ($packageInfo in $script:CompromisedPackages) {
                $parts = $packageInfo -split ':'
                $packageName = $parts[0]
                $maliciousVersion = $parts[1]
                
                # Check for package in lockfile with specific version
                if ($content -match [regex]::Escape($packageName) -and $content -match [regex]::Escape($maliciousVersion)) {
                    # Try to verify it's the actual package version, not just a coincidental match
                    if ($content -match "`"$([regex]::Escape($packageName))`".*`"$([regex]::Escape($maliciousVersion))`"" -or
                        $content -match "$([regex]::Escape($packageName))@$([regex]::Escape($maliciousVersion))") {
                        Add-Finding -FileName "integrity_issues.txt" -Content "$($lockfile.FullName):Compromised package in lockfile: $packageName@$maliciousVersion"
                    }
                }
            }
            
            # Check for recently modified lockfiles with @ctrl packages
            if ($content -match "@ctrl") {
                $fileAge = (Get-Date) - (Get-Item $lockfile.FullName).LastWriteTime
                if ($fileAge.TotalDays -lt 30) {
                    Add-Finding -FileName "integrity_issues.txt" -Content "$($lockfile.FullName):Recently modified lockfile contains @ctrl packages (potential worm activity)"
                }
            }
        }
        catch {
            # Skip files that can't be read
        }
    }
}

function Test-Typosquatting {
    <#
    .SYNOPSIS
        Detect typosquatting and homoglyph attacks
    #>
    param([string]$ScanDir)
    
    $popularPackages = @(
        "react", "vue", "angular", "express", "lodash", "axios", "typescript"
        "webpack", "babel", "eslint", "jest", "mocha", "chalk", "debug"
        "commander", "inquirer", "yargs", "request", "moment", "underscore"
        "jquery", "bootstrap", "socket.io", "redis", "mongoose", "passport"
    )
    
    $warnedPackages = @{}
    
    Get-ChildItem -Path $ScanDir -Recurse -Filter "package.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
            $json = $content | ConvertFrom-Json -ErrorAction Stop
            $filePath = $_.FullName
            
            # Collect all package names
            $packageNames = @()
            @("dependencies", "devDependencies", "peerDependencies", "optionalDependencies") | ForEach-Object {
                if ($json.PSObject.Properties[$_]) {
                    $json.$_.PSObject.Properties | ForEach-Object {
                        $packageNames += $_.Name
                    }
                }
            }
            
            foreach ($packageName in $packageNames | Sort-Object -Unique) {
                if ([string]::IsNullOrWhiteSpace($packageName) -or $packageName.Length -lt 2) { continue }
                
                $warnKey = "$filePath`:$packageName"
                if ($warnedPackages.ContainsKey($warnKey)) { continue }
                
                # Check for non-ASCII characters
                if ($packageName -match '[^\x00-\x7F]') {
                    Add-Finding -FileName "typosquatting_warnings.txt" -Content "$filePath`:Potential Unicode/homoglyph characters in package: $packageName"
                    $warnedPackages[$warnKey] = $true
                    continue
                }
                
                # Check for confusable patterns
                $confusables = @{
                    "rn" = "m"
                    "vv" = "w"
                    "cl" = "d"
                }
                
                foreach ($confusable in $confusables.GetEnumerator()) {
                    if ($packageName -match $confusable.Key) {
                        if (-not $warnedPackages.ContainsKey($warnKey)) {
                            Add-Finding -FileName "typosquatting_warnings.txt" -Content "$filePath`:Potential typosquatting pattern '$($confusable.Key)' in package: $packageName"
                            $warnedPackages[$warnKey] = $true
                        }
                    }
                }
                
                # Check similarity to popular packages
                foreach ($popular in $popularPackages) {
                    if ($packageName -eq $popular) { continue }
                    
                    # Single character difference for longer package names
                    if ($packageName.Length -eq $popular.Length -and $packageName.Length -gt 4) {
                        $diffCount = 0
                        for ($i = 0; $i -lt $packageName.Length; $i++) {
                            if ($packageName[$i] -ne $popular[$i]) {
                                $diffCount++
                            }
                        }
                        
                        if ($diffCount -eq 1 -and $packageName -notmatch "-" -and $popular -notmatch "-") {
                            if (-not $warnedPackages.ContainsKey($warnKey)) {
                                Add-Finding -FileName "typosquatting_warnings.txt" -Content "$filePath`:Potential typosquatting of '$popular': $packageName (1 char difference)"
                                $warnedPackages[$warnKey] = $true
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Skip files that can't be parsed
        }
    }
}

function Test-NetworkExfiltration {
    <#
    .SYNOPSIS
        Detect network exfiltration patterns
    #>
    param([string]$ScanDir)
    
    $suspiciousDomains = @(
        "pastebin.com", "hastebin.com", "ix.io", "0x0.st", "transfer.sh"
        "file.io", "anonfiles.com", "mega.nz", "dropbox.com/s/"
        "discord.com/api/webhooks", "telegram.org", "t.me"
        "ngrok.io", "localtunnel.me", "serveo.net"
        "requestbin.com", "webhook.site", "beeceptor.com"
        "pipedream.com", "zapier.com/hooks"
    )
    
    Get-ChildItem -Path $ScanDir -Recurse -Include "*.js", "*.ts", "*.json", "*.mjs" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "[\\/]node_modules[\\/]" -and $_.FullName -notmatch "[\\/]vendor[\\/]" } | ForEach-Object {
            try {
                $content = Get-Content -Path $_.FullName -Raw -ErrorAction Stop
                $filePath = $_.FullName
                
                # Check for hardcoded IP addresses
                if ($content -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
                    $ips = [regex]::Matches($content, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') | 
                           Select-Object -First 3 | ForEach-Object { $_.Value }
                    $ipsStr = $ips -join ", "
                    
                    if ($ipsStr -notmatch "127\.0\.0\.1" -and $ipsStr -notmatch "0\.0\.0\.0") {
                        Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:Hardcoded IP addresses found: $ipsStr"
                    }
                }
                
                # Check for suspicious domains
                foreach ($domain in $suspiciousDomains) {
                    $escapedDomain = [regex]::Escape($domain)
                    if ($content -match "https?://[^\s]*$escapedDomain|[\s:,`"']$escapedDomain[\s/`"',;]") {
                        Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:Suspicious domain found: $domain"
                    }
                }
                
                # Check for base64-encoded URLs
                if ($content -match "atob\(" -or $content -match "base64.*decode") {
                    Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:Base64 decoding detected"
                }
                
                # Check for DNS-over-HTTPS patterns
                if ($content -match "dns-query" -or $content -match "application/dns-message") {
                    Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:DNS-over-HTTPS pattern detected"
                }
                
                # Check for WebSocket connections
                if ($content -match "wss?://") {
                    $wsMatches = [regex]::Matches($content, 'wss?://[^"''\s]+')
                    foreach ($match in $wsMatches) {
                        $endpoint = $match.Value
                        if ($endpoint -notmatch "localhost" -and $endpoint -notmatch "127\.0\.0\.1") {
                            Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:WebSocket connection to external endpoint: $endpoint"
                        }
                    }
                }
                
                # Check for suspicious HTTP headers
                if ($content -match "X-Exfiltrate|X-Data-Export|X-Credential") {
                    Add-Finding -FileName "network_exfiltration_warnings.txt" -Content "$filePath`:Suspicious HTTP headers detected"
                }
            }
            catch {
                # Skip files that can't be read
            }
        }
}

#endregion

#region Report Generation

function Write-Report {
    <#
    .SYNOPSIS
        Generate comprehensive security report
    #>
    param([bool]$ParanoidMode)

    # Temporarily disable strict mode for report generation to avoid .Count issues
    Set-StrictMode -Off

    Write-Host ""
    Write-StatusBlue "=============================================="
    if ($ParanoidMode) {
        Write-StatusBlue "  SHAI-HULUD + PARANOID SECURITY REPORT"
    }
    else {
        Write-StatusBlue "      SHAI-HULUD DETECTION REPORT"
    }
    Write-StatusBlue "=============================================="
    Write-Host ""
    
    $script:HighRisk = 0
    $script:MediumRisk = 0
    
    # Report malicious workflow files
    if (Test-FindingsExist -FileName "workflow_files.txt") {
        Write-StatusRed "🚨 HIGH RISK: Malicious workflow files detected:"
        foreach ($file in (Get-Findings -FileName "workflow_files.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: Known malicious workflow filename"
            $script:HighRisk++
        }
    }
    
    # Report malicious file hashes
    if (Test-FindingsExist -FileName "malicious_hashes.txt") {
        Write-StatusRed "🚨 HIGH RISK: Files with known malicious hashes:"
        foreach ($entry in (Get-Findings -FileName "malicious_hashes.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $hash = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - $filePath"
            Write-Host "     Hash: $hash"
            Show-FilePreview -FilePath $filePath -Context "HIGH RISK: File matches known malicious SHA-256 hash"
            $script:HighRisk++
        }
    }
    
    # Report November 2025 Bun attack files
    if (Test-FindingsExist -FileName "bun_setup_files.txt") {
        Write-StatusRed "🚨 HIGH RISK: November 2025 Bun attack setup files detected:"
        foreach ($file in (Get-Findings -FileName "bun_setup_files.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: setup_bun.js - Fake Bun runtime installation malware"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "bun_environment_files.txt") {
        Write-StatusRed "🚨 HIGH RISK: November 2025 Bun environment payload detected:"
        foreach ($file in (Get-Findings -FileName "bun_environment_files.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: bun_environment.js - 10MB+ obfuscated credential harvesting payload"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "new_workflow_files.txt") {
        Write-StatusRed "🚨 HIGH RISK: November 2025 malicious workflow files detected:"
        foreach ($file in (Get-Findings -FileName "new_workflow_files.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: formatter_*.yml - Malicious GitHub Actions workflow"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "actions_secrets_files.txt") {
        Write-StatusRed "🚨 HIGH RISK: Actions secrets exfiltration files detected:"
        foreach ($file in (Get-Findings -FileName "actions_secrets_files.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: actionsSecrets.json - Double Base64 encoded secrets exfiltration"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "discussion_workflows.txt") {
        Write-StatusRed "🚨 HIGH RISK: Malicious discussion-triggered workflows detected:"
        foreach ($entry in (Get-Findings -FileName "discussion_workflows.txt")) {
            $parts = $entry -split ':', 2
            $file = $parts[0]
            $reason = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - $file"
            Write-Host "     Reason: $reason"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: Discussion workflow - Enables arbitrary command execution via GitHub discussions"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "github_runners.txt") {
        Write-StatusRed "🚨 HIGH RISK: Malicious GitHub Actions runners detected:"
        foreach ($entry in (Get-Findings -FileName "github_runners.txt")) {
            $parts = $entry -split ':', 2
            $dir = $parts[0]
            $reason = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - $dir"
            Write-Host "     Reason: $reason"
            Show-FilePreview -FilePath $dir -Context "HIGH RISK: GitHub Actions runner - Self-hosted backdoor for persistent access"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "destructive_patterns.txt") {
        Write-StatusRed "🚨 CRITICAL: Destructive payload patterns detected:"
        Write-StatusRed "    ⚠️  WARNING: These patterns can cause permanent data loss!"
        foreach ($entry in (Get-Findings -FileName "destructive_patterns.txt")) {
            $parts = $entry -split ':', 2
            $file = $parts[0]
            $patternInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - $file"
            Write-Host "     Pattern: $patternInfo"
            Show-FilePreview -FilePath $file -Context "CRITICAL: Destructive pattern - Can delete user files when credential theft fails"
            $script:HighRisk++
        }
        Write-StatusRed "    📋 IMMEDIATE ACTION REQUIRED: Quarantine these files and review for data destruction capabilities"
    }
    
    if (Test-FindingsExist -FileName "preinstall_bun_patterns.txt") {
        Write-StatusRed "🚨 HIGH RISK: Fake Bun preinstall patterns detected:"
        foreach ($file in (Get-Findings -FileName "preinstall_bun_patterns.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: package.json contains malicious preinstall: node setup_bun.js"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "github_sha1hulud_runners.txt") {
        Write-StatusRed "🚨 HIGH RISK: SHA1HULUD GitHub Actions runners detected:"
        foreach ($file in (Get-Findings -FileName "github_sha1hulud_runners.txt")) {
            Write-Host "   - $file"
            Show-FilePreview -FilePath $file -Context "HIGH RISK: GitHub Actions workflow contains SHA1HULUD runner references"
            $script:HighRisk++
        }
    }
    
    if (Test-FindingsExist -FileName "second_coming_repos.txt") {
        Write-StatusRed "🚨 HIGH RISK: 'Shai-Hulud: The Second Coming' repositories detected:"
        foreach ($repoDir in (Get-Findings -FileName "second_coming_repos.txt")) {
            Write-Host "   - $repoDir"
            Write-Host "     Repository description: Sha1-Hulud: The Second Coming."
            $script:HighRisk++
        }
    }
    
    # Report compromised packages
    if (Test-FindingsExist -FileName "compromised_found.txt") {
        Write-StatusRed "🚨 HIGH RISK: Compromised package versions detected:"
        foreach ($entry in (Get-Findings -FileName "compromised_found.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $packageInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Package: $packageInfo"
            Write-Host "     Found in: $filePath"
            Show-FilePreview -FilePath $filePath -Context "HIGH RISK: Contains compromised package version: $packageInfo"
            $script:HighRisk++
        }
        Write-StatusYellow "   NOTE: These specific package versions are known to be compromised."
        Write-StatusYellow "   You should immediately update or remove these packages."
        Write-Host ""
    }
    
    # Report suspicious packages
    if (Test-FindingsExist -FileName "suspicious_found.txt") {
        Write-StatusYellow "⚠️  MEDIUM RISK: Suspicious package versions detected:"
        foreach ($entry in (Get-Findings -FileName "suspicious_found.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $packageInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Package: $packageInfo"
            Write-Host "     Found in: $filePath"
            $script:MediumRisk++
        }
        Write-StatusYellow "   NOTE: Manual review required to determine if these are malicious."
        Write-Host ""
    }
    
    # Report lockfile-safe packages
    if (Test-FindingsExist -FileName "lockfile_safe_versions.txt") {
        Write-StatusBlue "ℹ️  LOW RISK: Packages with safe lockfile versions:"
        foreach ($entry in (Get-Findings -FileName "lockfile_safe_versions.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $packageInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Package: $packageInfo"
            Write-Host "     Found in: $filePath"
        }
        Write-StatusBlue "   NOTE: These package.json ranges could match compromised versions, but lockfiles pin to safe versions."
        Write-StatusBlue "   Your current installation is safe. Avoid running 'npm update' without reviewing changes."
        Write-Host ""
    }
    
    # Report suspicious content
    if (Test-FindingsExist -FileName "suspicious_content.txt") {
        Write-StatusYellow "⚠️  MEDIUM RISK: Suspicious content patterns:"
        foreach ($entry in (Get-Findings -FileName "suspicious_content.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $pattern = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Pattern: $pattern"
            Write-Host "     Found in: $filePath"
            $script:MediumRisk++
        }
        Write-StatusYellow "   NOTE: Manual review required to determine if these are malicious."
        Write-Host ""
    }
    
    # Report cryptocurrency theft patterns
    if (Test-FindingsExist -FileName "crypto_patterns.txt") {
        $cryptoFindings = Get-Findings -FileName "crypto_patterns.txt"
        $highRiskCrypto = $cryptoFindings | Where-Object { $_ -match "HIGH RISK|Known attacker wallet" }
        $mediumRiskCrypto = $cryptoFindings | Where-Object { $_ -notmatch "HIGH RISK|Known attacker wallet" -and $_ -notmatch "LOW RISK" }
        $lowRiskCrypto = $cryptoFindings | Where-Object { $_ -match "LOW RISK" }
        
        if ($highRiskCrypto) {
            Write-StatusRed "🚨 HIGH RISK: Cryptocurrency theft patterns detected:"
            foreach ($entry in $highRiskCrypto) {
                Write-Host "   - $entry"
                $script:HighRisk++
            }
            Write-StatusRed "   NOTE: These patterns strongly indicate crypto theft malware from the September 8 attack."
            Write-StatusRed "   Immediate investigation and remediation required."
            Write-Host ""
        }
        
        if ($mediumRiskCrypto) {
            Write-StatusYellow "⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:"
            foreach ($entry in $mediumRiskCrypto) {
                Write-Host "   - $entry"
                $script:MediumRisk++
            }
            Write-StatusYellow "   NOTE: These may be legitimate crypto tools or framework code."
            Write-StatusYellow "   Manual review recommended to determine if they are malicious."
            Write-Host ""
        }
        
        # Add low risk crypto findings to low_risk_findings
        foreach ($entry in $lowRiskCrypto) {
            Add-Finding -FileName "low_risk_findings.txt" -Content "Crypto pattern: $entry"
        }
    }
    
    # Report git branches
    if (Test-FindingsExist -FileName "git_branches.txt") {
        Write-StatusYellow "⚠️  MEDIUM RISK: Suspicious git branches:"
        foreach ($entry in (Get-Findings -FileName "git_branches.txt")) {
            $parts = $entry -split ':', 2
            $repoPath = $parts[0]
            $branchInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Repository: $repoPath"
            Write-Host "     $branchInfo"
            Write-Host "     ┌─ Git Investigation Commands:" -ForegroundColor Cyan
            Write-Host "     │  cd '$repoPath'" -ForegroundColor Cyan
            Write-Host "     │  git log --oneline -10 shai-hulud" -ForegroundColor Cyan
            Write-Host "     │  git show shai-hulud" -ForegroundColor Cyan
            Write-Host "     │  git diff main...shai-hulud" -ForegroundColor Cyan
            Write-Host "     └─" -ForegroundColor Cyan
            Write-Host ""
            $script:MediumRisk++
        }
        Write-StatusYellow "   NOTE: 'shai-hulud' branches may indicate compromise."
        Write-StatusYellow "   Use the commands above to investigate each branch."
        Write-Host ""
    }
    
    # Report suspicious postinstall hooks
    if (Test-FindingsExist -FileName "postinstall_hooks.txt") {
        Write-StatusRed "🚨 HIGH RISK: Suspicious postinstall hooks detected:"
        foreach ($entry in (Get-Findings -FileName "postinstall_hooks.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $hookInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Hook: $hookInfo"
            Write-Host "     Found in: $filePath"
            Show-FilePreview -FilePath $filePath -Context "HIGH RISK: Contains suspicious postinstall hook: $hookInfo"
            $script:HighRisk++
        }
        Write-StatusYellow "   NOTE: Postinstall hooks can execute arbitrary code during package installation."
        Write-StatusYellow "   Review these hooks carefully for malicious behavior."
        Write-Host ""
    }
    
    # Report Trufflehog activity by risk level
    if (Test-FindingsExist -FileName "trufflehog_activity.txt") {
        $trufflehogFindings = Get-Findings -FileName "trufflehog_activity.txt"
        $highRiskTrufflehog = $trufflehogFindings | Where-Object { $_ -match ":HIGH:" }
        $mediumRiskTrufflehog = $trufflehogFindings | Where-Object { $_ -match ":MEDIUM:" }
        $lowRiskTrufflehog = $trufflehogFindings | Where-Object { $_ -match ":LOW:" }
        
        if ($highRiskTrufflehog) {
            Write-StatusRed "🚨 HIGH RISK: Trufflehog/secret scanning activity detected:"
            foreach ($entry in $highRiskTrufflehog) {
                $parts = $entry -split ':HIGH:', 2
                $filePath = $parts[0]
                $activityInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
                Write-Host "   - Activity: $activityInfo"
                Write-Host "     Found in: $filePath"
                Show-FilePreview -FilePath $filePath -Context "HIGH RISK: $activityInfo"
                $script:HighRisk++
            }
            Write-StatusRed "   NOTE: These patterns indicate likely malicious credential harvesting."
            Write-StatusRed "   Immediate investigation and remediation required."
            Write-Host ""
        }
        
        if ($mediumRiskTrufflehog) {
            Write-StatusYellow "⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:"
            foreach ($entry in $mediumRiskTrufflehog) {
                $parts = $entry -split ':MEDIUM:', 2
                $filePath = $parts[0]
                $activityInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
                Write-Host "   - Pattern: $activityInfo"
                Write-Host "     Found in: $filePath"
                $script:MediumRisk++
            }
            Write-StatusYellow "   NOTE: These may be legitimate security tools or framework code."
            Write-StatusYellow "   Manual review recommended to determine if they are malicious."
            Write-Host ""
        }
        
        # Add low risk findings
        foreach ($entry in $lowRiskTrufflehog) {
            $parts = $entry -split ':LOW:', 2
            Add-Finding -FileName "low_risk_findings.txt" -Content "Trufflehog pattern: $($parts[0]):$($parts[1])"
        }
    }
    
    # Report Shai-Hulud repositories
    if (Test-FindingsExist -FileName "shai_hulud_repos.txt") {
        Write-StatusRed "🚨 HIGH RISK: Shai-Hulud repositories detected:"
        foreach ($entry in (Get-Findings -FileName "shai_hulud_repos.txt")) {
            $parts = $entry -split ':', 2
            $repoPath = $parts[0]
            $repoInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Repository: $repoPath"
            Write-Host "     $repoInfo"
            Write-Host "     ┌─ Repository Investigation Commands:" -ForegroundColor Cyan
            Write-Host "     │  cd '$repoPath'" -ForegroundColor Cyan
            Write-Host "     │  git log --oneline -10" -ForegroundColor Cyan
            Write-Host "     │  git remote -v" -ForegroundColor Cyan
            Write-Host "     │  dir" -ForegroundColor Cyan
            Write-Host "     └─" -ForegroundColor Cyan
            Write-Host ""
            $script:HighRisk++
        }
        Write-StatusYellow "   NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration."
        Write-StatusYellow "   These should be deleted immediately after investigation."
        Write-Host ""
    }
    
    # Store namespace warnings as LOW risk
    if (Test-FindingsExist -FileName "namespace_warnings.txt") {
        foreach ($entry in (Get-Findings -FileName "namespace_warnings.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $namespaceInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Add-Finding -FileName "low_risk_findings.txt" -Content "Namespace warning: $namespaceInfo (found in $(Split-Path -Leaf $filePath))"
        }
    }
    
    # Report package integrity issues
    if (Test-FindingsExist -FileName "integrity_issues.txt") {
        Write-StatusYellow "⚠️  MEDIUM RISK: Package integrity issues detected:"
        foreach ($entry in (Get-Findings -FileName "integrity_issues.txt")) {
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $issueInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Issue: $issueInfo"
            Write-Host "     Found in: $filePath"
            $script:MediumRisk++
        }
        Write-StatusYellow "   NOTE: These issues may indicate tampering with package dependencies."
        Write-StatusYellow "   Verify package versions and regenerate lockfiles if necessary."
        Write-Host ""
    }
    
    # Report typosquatting warnings (paranoid mode only)
    if ($ParanoidMode -and (Test-FindingsExist -FileName "typosquatting_warnings.txt")) {
        Write-StatusYellow "⚠️  MEDIUM RISK (PARANOID): Potential typosquatting/homoglyph attacks detected:"
        $typoFindings = @(Get-Findings -FileName "typosquatting_warnings.txt")
        $typoCount = 0
        foreach ($entry in $typoFindings) {
            if ($typoCount -ge 5) { break }
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $warningInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Warning: $warningInfo"
            Write-Host "     Found in: $filePath"
            $script:MediumRisk++
            $typoCount++
        }
        if ($typoFindings.Count -gt 5) {
            Write-Host "   - ... and $($typoFindings.Count - 5) more typosquatting warnings (truncated for brevity)"
        }
        Write-StatusYellow "   NOTE: These packages may be impersonating legitimate packages."
        Write-StatusYellow "   Verify package names carefully and check if they should be legitimate packages."
        Write-Host ""
    }
    
    # Report network exfiltration warnings (paranoid mode only)
    if ($ParanoidMode -and (Test-FindingsExist -FileName "network_exfiltration_warnings.txt")) {
        Write-StatusYellow "⚠️  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
        $netFindings = @(Get-Findings -FileName "network_exfiltration_warnings.txt")
        $netCount = 0
        foreach ($entry in $netFindings) {
            if ($netCount -ge 5) { break }
            $parts = $entry -split ':', 2
            $filePath = $parts[0]
            $warningInfo = if ($parts.Count -gt 1) { $parts[1] } else { "Unknown" }
            Write-Host "   - Warning: $warningInfo"
            Write-Host "     Found in: $filePath"
            $script:MediumRisk++
            $netCount++
        }
        if ($netFindings.Count -gt 5) {
            Write-Host "   - ... and $($netFindings.Count - 5) more network warnings (truncated for brevity)"
        }
        Write-StatusYellow "   NOTE: These patterns may indicate data exfiltration or communication with C2 servers."
        Write-StatusYellow "   Review network connections and data flows carefully."
        Write-Host ""
    }
    
    $totalIssues = $script:HighRisk + $script:MediumRisk
    $lowRiskFindings = @(Get-Findings -FileName "low_risk_findings.txt")
    $lowRiskCount = $lowRiskFindings.Count
    
    # Summary
    Write-StatusBlue "=============================================="
    if ($totalIssues -eq 0) {
        Write-StatusGreen "✅ No indicators of Shai-Hulud compromise detected."
        Write-StatusGreen "Your system appears clean from this specific attack."
        
        # Show low risk findings if any
        if ($lowRiskCount -gt 0) {
            Write-Host ""
            Write-StatusBlue "ℹ️  LOW RISK FINDINGS (informational only):"
            foreach ($finding in $lowRiskFindings) {
                Write-Host "   - $finding"
            }
            Write-StatusBlue "   NOTE: These are likely legitimate framework code or dependencies."
        }
    }
    else {
        Write-StatusRed "🔍 SUMMARY:"
        Write-StatusRed "   High Risk Issues: $($script:HighRisk)"
        Write-StatusYellow "   Medium Risk Issues: $($script:MediumRisk)"
        if ($lowRiskCount -gt 0) {
            Write-StatusBlue "   Low Risk (informational): $lowRiskCount"
        }
        Write-StatusBlue "   Total Critical Issues: $totalIssues"
        Write-Host ""
        Write-StatusYellow "⚠️  IMPORTANT:"
        Write-StatusYellow "   - High risk issues likely indicate actual compromise"
        Write-StatusYellow "   - Medium risk issues require manual investigation"
        Write-StatusYellow "   - Low risk issues are likely false positives from legitimate code"
        if ($ParanoidMode) {
            Write-StatusYellow "   - Issues marked (PARANOID) are general security checks, not Shai-Hulud specific"
        }
        Write-StatusYellow "   - Consider running additional security scans"
        Write-StatusYellow "   - Review your npm audit logs and package history"
        
        if ($lowRiskCount -gt 0 -and $totalIssues -lt 5) {
            Write-Host ""
            Write-StatusBlue "ℹ️  LOW RISK FINDINGS (likely false positives):"
            foreach ($finding in $lowRiskFindings) {
                Write-Host "   - $finding"
            }
            Write-StatusBlue "   NOTE: These are typically legitimate framework patterns."
        }
    }
    Write-StatusBlue "=============================================="
}

#endregion

#region Main Entry Point

function Invoke-Main {
    <#
    .SYNOPSIS
        Main entry point
    #>
    param(
        [string]$ScanDir,
        [bool]$ParanoidMode
    )
    
    # Load compromised packages
    Import-CompromisedPackages
    
    # Create temporary directory
    New-TempDirectory
    
    try {
        # Convert to absolute path
        $ScanDir = (Resolve-Path $ScanDir).Path
        
        Write-StatusGreen "Starting Shai-Hulud detection scan..."
        if ($ParanoidMode) {
            Write-StatusBlue "Scanning directory: $ScanDir (with paranoid mode enabled)"
        }
        else {
            Write-StatusBlue "Scanning directory: $ScanDir"
        }
        Write-Host ""
        
        # Run core Shai-Hulud detection checks
        Test-WorkflowFiles -ScanDir $ScanDir
        Test-FileHashes -ScanDir $ScanDir
        Test-Packages -ScanDir $ScanDir
        Test-PostinstallHooks -ScanDir $ScanDir
        Test-SuspiciousContent -ScanDir $ScanDir
        Test-CryptoTheftPatterns -ScanDir $ScanDir
        Test-TrufflehogActivity -ScanDir $ScanDir
        Test-GitBranches -ScanDir $ScanDir
        Test-ShaiHuludRepos -ScanDir $ScanDir
        Test-PackageIntegrity -ScanDir $ScanDir
        
        # November 2025 "Shai-Hulud: The Second Coming" attack detection
        Test-BunAttackFiles -ScanDir $ScanDir
        Test-NewWorkflowPatterns -ScanDir $ScanDir
        Test-DiscussionWorkflows -ScanDir $ScanDir
        Test-GitHubRunners -ScanDir $ScanDir
        Test-DestructivePatterns -ScanDir $ScanDir
        Test-PreinstallBunPatterns -ScanDir $ScanDir
        Test-GitHubActionsRunner -ScanDir $ScanDir
        Test-SecondComingRepos -ScanDir $ScanDir
        
        # Run additional security checks only in paranoid mode
        if ($ParanoidMode) {
            Write-StatusBlue "[Paranoid] Checking for typosquatting and homoglyph attacks..."
            Test-Typosquatting -ScanDir $ScanDir
            Write-StatusBlue "[Paranoid] Checking for network exfiltration patterns..."
            Test-NetworkExfiltration -ScanDir $ScanDir
        }
        
        # Generate report and save to file
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $reportFile = Join-Path $ScanDir "shai-hulud-report_$timestamp.txt"

        Write-Host ""
        Write-StatusGreen "📝 Generating report and saving to: $reportFile"
        Write-Host ""

        # Start transcript to capture report
        Start-Transcript -Path $reportFile -Force | Out-Null

        Write-Report -ParanoidMode $ParanoidMode

        # Stop transcript
        Stop-Transcript | Out-Null

        Write-Host ""
        Write-StatusGreen "✅ Report saved to: $reportFile"
        Write-Host ""

        # Return appropriate exit code based on findings
        if ($script:HighRisk -gt 0) {
            exit 1  # High risk findings detected
        }
        elseif ($script:MediumRisk -gt 0) {
            exit 2  # Medium risk findings detected
        }
        else {
            exit 0  # Clean - no significant findings
        }
    }
    finally {
        # Cleanup
        Remove-TempDirectory
    }
}

# Run main function
if ($Paranoid -is [System.Management.Automation.SwitchParameter]) {
    Invoke-Main -ScanDir $Path -ParanoidMode $Paranoid.IsPresent
}
else {
    Invoke-Main -ScanDir $Path -ParanoidMode $Paranoid
}

#endregion
