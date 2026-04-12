#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Harden Windows against encryption key leakage via hibernation and page file.

.DESCRIPTION
    VeraCrypt keeps decryption keys in RAM while volumes are mounted. Hibernation
    writes RAM to hiberfil.sys, and the Windows page file may contain key material
    paged out of RAM. This script disables hibernation and checks whether the
    system drive is encrypted (which protects the page file).

    Must be run as Administrator. Safe to run multiple times (idempotent).

.PARAMETER DisablePageFile
    Disable the page file entirely. WARNING: This can cause instability on systems
    with limited RAM. Only use if you understand the consequences.

.PARAMETER NonInteractive
    Skip all confirmation prompts. Use for automated deployments.
#>

[CmdletBinding()]
param(
    [switch]$DisablePageFile,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

function Write-LogInfo  { param([string]$Message) Write-Host "[INFO]  $Message" }
function Write-LogWarn  { param([string]$Message) Write-Host "[WARN]  $Message" -ForegroundColor Yellow }
function Write-LogError { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-LogOk    { param([string]$Message) Write-Host "[OK]    $Message" -ForegroundColor Green }

function Confirm-Action {
    param([string]$Prompt)
    if ($NonInteractive) { return $true }
    $answer = Read-Host "$Prompt [y/N]"
    return ($answer -match '^[Yy]$')
}

# --------------------------------------------------------------------------- #
# Pre-flight: verify Administrator
# --------------------------------------------------------------------------- #

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-LogError "This script must be run as Administrator."
    Write-LogError "Right-click PowerShell and select 'Run as administrator', then try again."
    exit 1
}

# --------------------------------------------------------------------------- #
# 1. Disable hibernation
# --------------------------------------------------------------------------- #

Write-LogInfo "Disabling hibernation..."

# Check current hibernation state.
$hiberStatus = $null
try {
    $hiberStatus = (powercfg /a 2>&1) | Out-String
} catch {
    Write-LogWarn "Could not query power capabilities: $_"
}

try {
    $result = & powercfg /h off 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-LogWarn "powercfg /h off returned exit code $LASTEXITCODE. Output: $result"
    } else {
        Write-LogOk "Hibernation disabled (powercfg /h off)."
    }
} catch {
    Write-LogError "Failed to disable hibernation: $_"
    throw
}

# Verify hiberfil.sys is gone or will be removed on next reboot.
$hiberFile = "$env:SystemDrive\hiberfil.sys"
if (Test-Path $hiberFile) {
    Write-LogWarn "hiberfil.sys still exists at $hiberFile."
    Write-LogWarn "It should be removed automatically. If not, a reboot may be required."
} else {
    Write-LogOk "hiberfil.sys does not exist (hibernation file removed)."
}

# --------------------------------------------------------------------------- #
# 2. Disable fast startup (uses hibernation under the hood)
# --------------------------------------------------------------------------- #

Write-LogInfo "Disabling Fast Startup (hybrid shutdown)..."

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
try {
    $currentValue = Get-ItemProperty -Path $regPath -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
    if ($null -eq $currentValue -or $currentValue.HiberbootEnabled -ne 0) {
        Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0 -Type DWord
        Write-LogOk "Fast Startup disabled (HiberbootEnabled = 0)."
    } else {
        Write-LogOk "Fast Startup is already disabled."
    }
} catch {
    Write-LogWarn "Could not disable Fast Startup: $_"
    Write-LogWarn "Manually disable via: Control Panel > Power Options > Choose what the power buttons do > Change settings > uncheck 'Turn on fast startup'"
}

# --------------------------------------------------------------------------- #
# 3. Check system drive encryption status
# --------------------------------------------------------------------------- #

Write-LogInfo "Checking system drive encryption..."

$systemDrive = $env:SystemDrive  # e.g., "C:"
$systemEncrypted = $false
$veracryptSystemEncrypted = $false
$bitlockerEncrypted = $false

# Check BitLocker status.
try {
    $blStatus = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
    if ($null -ne $blStatus) {
        if ($blStatus.ProtectionStatus -eq "On") {
            $bitlockerEncrypted = $true
            $systemEncrypted = $true
            Write-LogOk "System drive $systemDrive is encrypted with BitLocker."
            Write-LogOk "Page file is protected by BitLocker encryption."
        } else {
            Write-LogWarn "BitLocker is present on $systemDrive but protection is $($blStatus.ProtectionStatus)."
        }
    }
} catch {
    Write-LogInfo "BitLocker cmdlet not available or failed: $($_.Exception.Message)"
}

# Check VeraCrypt system encryption.
# VeraCrypt system encryption is detected via its boot loader or driver.
$veracryptDriverLoaded = $false
try {
    $vcDriver = Get-Service -Name "veracrypt" -ErrorAction SilentlyContinue
    if ($null -ne $vcDriver -and $vcDriver.Status -eq "Running") {
        $veracryptDriverLoaded = $true
    }
} catch {
    # Service query failed, not fatal.
}

# Also check for VeraCrypt system encryption via registry.
$vcRegPath = "HKLM:\SOFTWARE\VeraCrypt"
$vcSysEncrypted = $false
try {
    if (Test-Path $vcRegPath) {
        Write-LogInfo "VeraCrypt registry key found."
        # VeraCrypt system encryption also installs a boot loader.
        # Check if the VeraCrypt driver is present.
        $vcDriverPath = "$env:SystemRoot\System32\drivers\veracrypt.sys"
        if (Test-Path $vcDriverPath) {
            Write-LogInfo "VeraCrypt driver found at $vcDriverPath."
            if ($veracryptDriverLoaded) {
                Write-LogInfo "VeraCrypt driver is loaded and running."
            }
        }
    }
} catch {
    # Non-fatal.
}

# Try veracrypt CLI to check system encryption.
$veracryptExe = $null
$possiblePaths = @(
    "${env:ProgramFiles}\VeraCrypt\VeraCrypt.exe",
    "${env:ProgramFiles(x86)}\VeraCrypt\VeraCrypt.exe"
)
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $veracryptExe = $path
        break
    }
}

if ($null -ne $veracryptExe) {
    Write-LogInfo "VeraCrypt found at: $veracryptExe"
    try {
        # VeraCrypt Format /sysenc can check, but it's interactive.
        # Instead, check for VeraCrypt boot loader signature.
        $formatExe = Join-Path (Split-Path $veracryptExe) "VeraCrypt Format.exe"
        if (Test-Path $formatExe) {
            Write-LogInfo "VeraCrypt Format tool available. To verify system encryption, run:"
            Write-LogInfo "  & '$veracryptExe' /v /q"
        }
    } catch {
        # Non-fatal.
    }
} else {
    Write-LogInfo "VeraCrypt executable not found in standard locations."
}

if (-not $systemEncrypted) {
    Write-Host ""
    Write-LogWarn "============================================================"
    Write-LogWarn "System drive $systemDrive does NOT appear to be encrypted."
    Write-LogWarn "============================================================"
    Write-LogWarn ""
    Write-LogWarn "The Windows page file (pagefile.sys) stores memory pages on disk."
    Write-LogWarn "Encryption keys from VeraCrypt containers can be paged out and"
    Write-LogWarn "recovered from an unencrypted page file."
    Write-LogWarn ""
    Write-LogWarn "Recommended mitigations (pick one):"
    Write-LogWarn "  1. Enable BitLocker on the system drive (best option)"
    Write-LogWarn "  2. Enable VeraCrypt system encryption"
    Write-LogWarn "  3. Disable the page file (risky on low-RAM systems)"
    Write-LogWarn "  4. Configure Windows to clear the page file on shutdown:"
    Write-LogWarn "     (slow shutdown, does NOT protect against power-off attacks)"
    Write-LogWarn ""
}

# --------------------------------------------------------------------------- #
# 4. Handle page file
# --------------------------------------------------------------------------- #

if ($DisablePageFile) {
    Write-Host ""
    Write-LogWarn "Page file disable requested."
    Write-LogWarn "WARNING: Disabling the page file can cause instability, blue screens,"
    Write-LogWarn "and application crashes on systems with limited RAM."

    if (-not (Confirm-Action "Disable the page file on all drives?")) {
        Write-LogInfo "Page file disable aborted."
    } else {
        try {
            # Disable automatic page file management.
            $cs = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
            if ($cs.AutomaticManagedPagefile) {
                $cs.AutomaticManagedPagefile = $false
                $cs.Put() | Out-Null
                Write-LogOk "Disabled automatic page file management."
            } else {
                Write-LogOk "Automatic page file management is already disabled."
            }

            # Remove page file from all drives.
            $pageFiles = Get-WmiObject -Class Win32_PageFileSetting
            if ($null -ne $pageFiles) {
                foreach ($pf in $pageFiles) {
                    $pf.Delete() | Out-Null
                    Write-LogOk "Removed page file setting: $($pf.Name)"
                }
            } else {
                Write-LogOk "No page file settings to remove."
            }

            Write-LogOk "Page file disabled. A reboot is required for this to take effect."
        } catch {
            Write-LogError "Failed to disable page file: $_"
            throw
        }
    }
} elseif (-not $systemEncrypted) {
    # If system is not encrypted, at least configure page file clearing on shutdown.
    Write-LogInfo "Configuring page file to clear on shutdown..."
    $clearRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    try {
        $currentClear = Get-ItemProperty -Path $clearRegPath -Name "ClearPageFileAtShutdown" -ErrorAction SilentlyContinue
        if ($null -eq $currentClear -or $currentClear.ClearPageFileAtShutdown -ne 1) {
            Set-ItemProperty -Path $clearRegPath -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord
            Write-LogOk "Page file will be cleared on shutdown (ClearPageFileAtShutdown = 1)."
            Write-LogWarn "Note: This slows down shutdown and does NOT protect against sudden power loss."
        } else {
            Write-LogOk "Page file clearing on shutdown is already enabled."
        }
    } catch {
        Write-LogWarn "Could not configure page file clearing: $_"
    }
}

# --------------------------------------------------------------------------- #
# 5. Additional: disable crash dumps (memory.dmp can contain keys)
# --------------------------------------------------------------------------- #

Write-LogInfo "Checking crash dump settings..."

$crashRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
try {
    $currentDump = Get-ItemProperty -Path $crashRegPath -Name "CrashDumpEnabled" -ErrorAction SilentlyContinue
    if ($null -ne $currentDump -and $currentDump.CrashDumpEnabled -ne 0) {
        Write-LogWarn "Crash dumps are enabled (CrashDumpEnabled = $($currentDump.CrashDumpEnabled))."
        Write-LogWarn "Memory dumps (memory.dmp) can contain encryption keys."
        Write-LogWarn "To disable: Set-ItemProperty -Path '$crashRegPath' -Name 'CrashDumpEnabled' -Value 0"
    } elseif ($null -ne $currentDump -and $currentDump.CrashDumpEnabled -eq 0) {
        Write-LogOk "Crash dumps are disabled."
    }
} catch {
    Write-LogWarn "Could not check crash dump settings: $_"
}

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

Write-Host ""
Write-LogInfo "=== Windows Hardening Summary ==="
Write-LogInfo "  Hibernation:    disabled"
Write-LogInfo "  Fast Startup:   disabled"
if ($systemEncrypted) {
    Write-LogInfo "  System drive:   encrypted (page file protected)"
} else {
    Write-LogInfo "  System drive:   NOT encrypted (page file at risk)"
}
if ($DisablePageFile) {
    Write-LogInfo "  Page file:      disabled (reboot required)"
} elseif (-not $systemEncrypted) {
    Write-LogInfo "  Page file:      clearing on shutdown enabled"
}
Write-Host ""
Write-LogInfo "To undo hibernation: powercfg /h on"
Write-LogInfo "To undo Fast Startup: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 1"
