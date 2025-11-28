# Installation & Setup Guide

## Quick Setup (5 minutes)

### Step 1: Download

```powershell
# Clone or download the repository
git clone https://github.com/FritzDerFred/shai-hulud-detector.git
cd shai-hulud-detector
```

Or download ZIP and extract to a folder.

### Step 2: Verify Files

Ensure you have:
- `shai-hulud-detector.ps1` - Main scanner script
- `compromised-packages.txt` - Malware database (1676+ packages)
- `README.md` - Documentation

### Step 3: Run

```powershell
# Option A: Double-click the script (opens interactive mode)
# Option B: Run from PowerShell
.\shai-hulud-detector.ps1
```

That's it! The script handles everything else automatically.

---

## Detailed Setup

### System Requirements

| Requirement | Version | Required | Notes |
|------------|---------|----------|-------|
| Windows | 10/11 or Server 2016+ | ✅ Yes | - |
| PowerShell | 5.1+ | ✅ Yes | Built into Windows |
| Administrator | Yes | ✅ Yes | Auto-requested |
| Node.js | Any | ⚠️ Recommended | For full npm analysis |
| npm | Any | ⚠️ Recommended | For package verification |

### Pre-Flight Checklist

Before scanning, verify:

1. ✅ **PowerShell 5.1+** installed
   ```powershell
   $PSVersionTable.PSVersion
   ```

2. ✅ **Admin access** available
   The script will prompt for elevation

3. ✅ **Node.js/npm** installed (optional but recommended)
   ```powershell
   node --version
   npm --version
   ```

4. ✅ **Execution Policy** allows scripts
   ```powershell
   Get-ExecutionPolicy
   # If Restricted, run:
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

---

## First Run

### Interactive Mode (Recommended for First Time)

1. **Start the scanner:**
   ```powershell
   .\shai-hulud-detector.ps1
   ```

2. **System Pre-Flight Check** appears:
   ```
   ============================================
           SYSTEM PRE-FLIGHT CHECK
   ============================================

   [✓] PowerShell Version: 5.1
   [✓] Administrator Rights: ACTIVE
   [✓] Malware Database: Found (1676 packages)
   [✓] npm found: C:\Program Files\nodejs\npm.cmd
   [✓] Node.js found: C:\Program Files\nodejs\node.exe

   ✅ System is ready!
   ```

3. **Enter scan path:**
   ```
   Which folder do you want to scan? (Enter path): C:\Projects\MyApp
   ```

4. **Choose Paranoid Mode:**
   ```
   Enable Paranoid Mode? (y/N): n
   ```

5. **Review Project Analysis:**
   ```
   PROJECT ANALYSIS:
   [✓] package.json found: 3 file(s)
   [✓] node_modules folders found: 3
   [✓] Lockfiles found: package-lock.json (npm)
   ```

6. **Confirm and start:**
   ```
   Ready to start!
   Press ENTER to start or CTRL+C to cancel: [ENTER]
   ```

7. **Watch the scan:**
   ```
   [Scanning 247/1000] \path\to\file.js
   [package.json 5/12] \path\to\package.json
   ```

8. **Review the report:**
   - Displayed on screen
   - Saved to: `shai-hulud-report_YYYY-MM-DD_HH-mm-ss.txt`

---

## Command-Line Mode (Advanced)

For automation or CI/CD:

```powershell
# Basic scan
.\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp"

# With Paranoid Mode
.\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp" -Paranoid

# Custom thread count
.\shai-hulud-detector.ps1 -Path "C:\Projects\MyApp" -Parallelism 8
```

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Clean | No significant threats found |
| 1 | High Risk | Confirmed malware detected - **INVESTIGATE IMMEDIATELY** |
| 2 | Medium Risk | Suspicious patterns found - Manual review recommended |

---

## What to Scan

### ✅ **Good Candidates:**

```powershell
# Your Node.js projects
.\shai-hulud-detector.ps1 -Path "C:\Users\You\Documents\Projects"

# Company repositories
.\shai-hulud-detector.ps1 -Path "C:\Work\Repositories"

# Downloaded npm projects
.\shai-hulud-detector.ps1 -Path "C:\Downloads\suspicious-project"

# Global npm packages
.\shai-hulud-detector.ps1 -Path "C:\Users\You\AppData\Roaming\npm"
```

### ❌ **Avoid Scanning:**

```powershell
# ❌ DON'T: Entire C:\ drive (takes hours!)
.\shai-hulud-detector.ps1 -Path "C:\"

# ❌ DON'T: Windows system folders (false positives)
.\shai-hulud-detector.ps1 -Path "C:\Windows"

# ❌ DON'T: Program Files (not npm projects)
.\shai-hulud-detector.ps1 -Path "C:\Program Files"
```

---

## Understanding Results

### High Risk (**ACT IMMEDIATELY**)

```
🚨 HIGH RISK: Compromised package versions detected:
   - Package: chalk@5.6.1
     Found in: C:\Project\package.json
```

**Actions:**
1. ⛔ **DO NOT RUN** `npm install` or `node`
2. 🔒 **QUARANTINE** the affected project
3. 🔍 **INVESTIGATE** - check git history for unauthorized changes
4. 🧹 **REMOVE** compromised packages
5. 🔄 **UPDATE** to safe versions
6. 🔐 **ROTATE** all credentials that may have been exposed

### Medium Risk (**REVIEW CAREFULLY**)

```
⚠️  MEDIUM RISK: Suspicious content patterns:
   - Pattern: webhook.site reference
     Found in: C:\Project\suspicious.js
```

**Actions:**
1. 👁️ **REVIEW** the flagged files manually
2. 📖 **CHECK** if it's legitimate code (could be false positive)
3. 🔍 **INVESTIGATE** context and purpose
4. 🛡️ **DECIDE** if action is needed

### Low Risk (**INFORMATIONAL**)

```
ℹ️  LOW RISK: XMLHttpRequest prototype modification detected
   - Found in: C:\Project\node_modules\axios\lib\adapters\xhr.js
```

**Actions:**
1. ✅ **USUALLY SAFE** - legitimate framework code
2. 📚 **DOCUMENT** for future reference
3. ⏭️ **CONTINUE** working normally

---

## Troubleshooting

### Issue: "Script cannot be loaded"

```
Error: File C:\path\shai-hulud-detector.ps1 cannot be loaded because
running scripts is disabled on this system.
```

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: "Admin rights requested but nothing happens"

**Solution:**
- Click "Yes" on UAC dialog
- If no dialog appears, right-click PowerShell → "Run as Administrator"
- Then navigate to script and run

### Issue: "npm not found"

```
[!] npm not found in system PATH
```

**Solution:**
- Scanner still works! (limited functionality)
- To enable full features: Install Node.js from [nodejs.org](https://nodejs.org/)

### Issue: "Path does not exist"

```
Error: Folder does not exist!
```

**Solution:**
- Verify path is correct
- Use full path: `C:\Users\You\Projects\MyApp`
- Avoid trailing slashes: ~~`C:\Projects\`~~ → `C:\Projects`

### Issue: Scan takes forever

**Symptoms:**
- No progress updates
- Appears frozen

**Solution:**
- You probably scanned `C:\` or a huge folder
- Press `CTRL+C` to cancel
- Scan a specific project folder instead

---

## Next Steps After Scan

### If Clean (Exit Code 0)

✅ **You're safe!** But:
1. Run scans periodically (weekly/monthly)
2. Scan after `npm install` from untrusted sources
3. Keep the compromised-packages database updated

### If Threats Found (Exit Code 1 or 2)

1. 📄 **Save the report** - Already saved automatically
2. 🔍 **Investigate** each finding
3. 🧹 **Clean** compromised packages
4. 🔄 **Re-scan** after cleanup
5. 🔐 **Security audit** - Check for data exfiltration
6. 🔑 **Rotate credentials** if HIGH RISK found

---

## Updating the Scanner

### Update Malware Database

```powershell
# Download latest compromised-packages.txt
# From repository or security advisories
```

### Update Scanner Script

```powershell
# Pull latest version
git pull origin main
```

---

## Getting Help

- 📖 **Full documentation**: See [README.md](README.md)
- 🐛 **Report bugs**: GitHub Issues
- 🔒 **Security issues**: GitHub Security Advisories
- 💬 **Questions**: GitHub Discussions

---

**Ready to scan? Let's go! 🚀**

```powershell
.\shai-hulud-detector.ps1
```
