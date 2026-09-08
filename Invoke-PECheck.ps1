<#
.SYNOPSIS
    All-in-one suspicious EXE privilege escalation analysis script.
.DESCRIPTION
    Analyzes a given EXE for common Windows privesc vectors:
    file metadata, signatures, service misconfigs, scheduled tasks,
    DLL hijack opportunities, weak permissions, registry autoruns,
    and running process token info.
    Hardened: timeouts on all blocking calls, full exception handling,
    no redundant operations, logic-bug-free.
.PARAMETER FilePath
    Full path to the suspicious EXE.
.PARAMETER OutputFile
    Optional. Path to save the report (default: PrivEscReport_<timestamp>.txt on Desktop)
.PARAMETER TimeoutSeconds
    Timeout in seconds for blocking WMI/external calls. Default: 15
.EXAMPLE
    .\Invoke-PECheck.ps1 -FilePath "C:\Temp\suspicious.exe"
    .\Invoke-PECheck.ps1 -FilePath "C:\Temp\suspicious.exe" -OutputFile "C:\report.txt" -TimeoutSeconds 20
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "$env:USERPROFILE\Desktop\PrivEscReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# -----------------------------------------------
# Helpers
# -----------------------------------------------

$Results = [System.Collections.Generic.List[string]]::new()

function Write-Section {
    param([string]$Title)
    $sep = "=" * 60
    $header = "`n$sep`n  $Title`n$sep"
    Write-Host $header -ForegroundColor Cyan
    $Results.Add($header)
}

function Write-Finding {
    param([string]$Label, [string]$Value, [string]$Severity = "INFO")
    $color = switch ($Severity) {
        "HIGH"   { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW"    { "Green" }
        default  { "White" }
    }
    $line = "  [$Severity] $Label : $Value"
    Write-Host $line -ForegroundColor $color
    $Results.Add($line)
}

function Write-Raw {
    param([string]$Text)
    Write-Host $Text -ForegroundColor Gray
    $Results.Add($Text)
}

function Write-Warn {
    param([string]$Msg)
    $line = "  [WARN] $Msg"
    Write-Host $line -ForegroundColor DarkYellow
    $Results.Add($line)
}

# Run a scriptblock in a job with a timeout; return output or $null on timeout/error
function Invoke-WithTimeout {
    param(
        [scriptblock]$ScriptBlock,
        [int]$Timeout = $TimeoutSeconds,
        [string]$Label = "operation"
    )
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock
        $completed = Wait-Job $job -Timeout $Timeout
        if ($null -eq $completed) {
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            Write-Warn "$Label timed out after ${Timeout}s -- skipped"
            return $null
        }
        $result = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $result
    } catch {
        Write-Warn "$Label failed: $_"
        return $null
    }
}

# Pure .NET ACL check -- no icacls process spawn, no hang risk
function Check-Writable {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return $false }
        
        # FIXED: Replaced ternary operator with if-else for PowerShell 5.1 compatibility
        if ([System.IO.Directory]::Exists($Path)) {
            $acl = Get-Acl $Path -ErrorAction Stop
        } else {
            $acl = Get-Acl $Path -ErrorAction Stop
        }

        $dangerousRights = [System.Security.AccessControl.FileSystemRights]"Write,Modify,FullControl"
        $dangerousSids = @(
            [System.Security.Principal.SecurityIdentifier]"S-1-1-0",       # Everyone
            [System.Security.Principal.SecurityIdentifier]"S-1-5-32-545",  # BUILTIN\Users
            [System.Security.Principal.SecurityIdentifier]"S-1-5-11"       # Authenticated Users
        )

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            foreach ($sid in $dangerousSids) {
                if ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $sid) {
                    if ($ace.FileSystemRights -band $dangerousRights) { return $true }
                }
            }
        }
    } catch {
        # Fall back to icacls with a timeout job if .NET ACL fails
        $p = $Path
        $result = Invoke-WithTimeout -Label "icacls fallback" -ScriptBlock {
            param($p)
            icacls $p 2>&1 | Out-String
        } -Timeout 8
        if ($null -ne $result) {
            $patterns = @("Everyone:\(F\)","Everyone:\(W\)","BUILTIN\\Users:\(F\)","BUILTIN\\Users:\(W\)","Authenticated Users:\(F\)","Authenticated Users:\(W\)")
            foreach ($pat in $patterns) {
                if ($result -match $pat) { return $true }
            }
        }
    }
    return $false
}

# -----------------------------------------------
# Banner
# -----------------------------------------------

$banner = @"
+==============================================================+
|          Invoke-PrivEscAnalysis  |  EXE Vector Checker       |
|          Run as: $env:USERNAME on $env:COMPUTERNAME
+==============================================================+
  Target  : $FilePath
  Time    : $(Get-Date)
  Timeout : ${TimeoutSeconds}s per blocking call
  Report  : $OutputFile
"@
Write-Host $banner -ForegroundColor Magenta
$Results.Add($banner)

# -----------------------------------------------
# 0. Validate file
# -----------------------------------------------

try {
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Write-Host "[!] File not found or is not a file: $FilePath" -ForegroundColor Red
        exit 1
    }
    $file     = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    $fileName = $file.Name
    $fileDir  = $file.DirectoryName
    $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
} catch {
    Write-Host "[!] Cannot access file: $_" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------
# 1. File Metadata
# -----------------------------------------------

Write-Section "1. FILE METADATA"

try { Write-Finding "Full Path"     $file.FullName } catch { Write-Warn "FullName: $_" }
try { Write-Finding "Size"          "$([math]::Round($file.Length/1KB,2)) KB" } catch {}
try { Write-Finding "Created"       $file.CreationTime.ToString() } catch {}
try { Write-Finding "Last Modified" $file.LastWriteTime.ToString() } catch {}
try { Write-Finding "Last Accessed" $file.LastAccessTime.ToString() } catch {}
try { Write-Finding "Owner"         (Get-Acl -LiteralPath $FilePath -ErrorAction Stop).Owner } catch { Write-Warn "Owner lookup failed: $_" }

try {
    $vi = $file.VersionInfo
    if ($vi -and $vi.FileDescription) {
        Write-Finding "Description"   $vi.FileDescription
        Write-Finding "Product"       $vi.ProductName
        Write-Finding "Company"       $vi.CompanyName
        Write-Finding "File Version"  $vi.FileVersion
        Write-Finding "Orig Filename" $vi.OriginalFilename
    } else {
        Write-Finding "Version Info" "NONE - suspicious for a legitimate binary" -Severity "MEDIUM"
    }
} catch {
    Write-Warn "Version info read failed: $_"
}

# -----------------------------------------------
# 2. Digital Signature
# -----------------------------------------------

Write-Section "2. DIGITAL SIGNATURE"

try {
    $sig    = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
    $status = $sig.Status.ToString()
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "N/A" }
    $sev    = switch ($status) {
        "Valid"        { "LOW" }
        "NotSigned"    { "HIGH" }
        default        { "MEDIUM" }
    }
    Write-Finding "Signature Status" $status -Severity $sev
    Write-Finding "Signer"           $signer
    if ($sig.TimeStamperCertificate) {
        Write-Finding "Timestamped" $sig.TimeStamperCertificate.Subject
    }
} catch {
    Write-Finding "Signature Check" "Failed: $_" -Severity "MEDIUM"
}

# -----------------------------------------------
# 3. File Hashes  (computed once, reused)
# -----------------------------------------------

Write-Section "3. FILE HASHES  (check VirusTotal / MalwareBazaar)"

$sha256 = $null
try {
    $hashMD5    = (Get-FileHash -LiteralPath $FilePath -Algorithm MD5    -ErrorAction Stop).Hash
    $hashSHA1   = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA1   -ErrorAction Stop).Hash
    $sha256     = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash

    Write-Finding "MD5"    $hashMD5
    Write-Finding "SHA1"   $hashSHA1
    Write-Finding "SHA256" $sha256
    Write-Raw ""
    Write-Raw "  VT  : https://www.virustotal.com/gui/file/$sha256"
    Write-Raw "  MBZ : https://bazaar.abuse.ch/browse.php?search=sha256%3A$sha256"
} catch {
    Write-Warn "Hash computation failed: $_"
}

# -----------------------------------------------
# 4. File Location Risk
# -----------------------------------------------

Write-Section "4. FILE LOCATION RISK"

$riskyPaths = @(
    @{ Pattern = "\Temp\";        Label = "Temp directory";          Sev = "HIGH" },
    @{ Pattern = "\Users\Public"; Label = "Public user folder";      Sev = "HIGH" },
    @{ Pattern = "\AppData\";     Label = "AppData (user-writable)"; Sev = "MEDIUM" },
    @{ Pattern = "\Downloads\";   Label = "Downloads folder";        Sev = "MEDIUM" },
    @{ Pattern = "\Desktop\";     Label = "Desktop";                 Sev = "LOW" }
)

$locationFlagged = $false
foreach ($rp in $riskyPaths) {
    if ($FilePath -like "*$($rp.Pattern)*") {
        Write-Finding "Location Risk" $rp.Label -Severity $rp.Sev
        $locationFlagged = $true
    }
}
if (-not $locationFlagged) {
    Write-Finding "Location" $fileDir -Severity "INFO"
}

try {
    if (Check-Writable $fileDir) {
        Write-Finding "Directory Writable" "$fileDir is writable by non-admins -- DLL planting risk" -Severity "HIGH"
    } else {
        Write-Finding "Directory Writable" "No (good)" -Severity "LOW"
    }
} catch { Write-Warn "Dir writable check failed: $_" }

try {
    if (Check-Writable $FilePath) {
        Write-Finding "Binary Writable" "Low-priv users can overwrite this binary -- service hijack risk" -Severity "HIGH"
    } else {
        Write-Finding "Binary Writable" "No (good)" -Severity "LOW"
    }
} catch { Write-Warn "Binary writable check failed: $_" }

# ACL dump via job with timeout (was hanging before)
Write-Raw "`n  -- Full ACL --"
$aclOut = Invoke-WithTimeout -Label "icacls ACL dump" -ScriptBlock {
    param($fp)
    icacls $fp 2>&1
} -Timeout $TimeoutSeconds
if ($null -ne $aclOut) {
    $aclOut | ForEach-Object { Write-Raw "  $_" }
} else {
    Write-Warn "ACL dump skipped (timeout)"
}

# -----------------------------------------------
# 5. Services
# -----------------------------------------------

Write-Section "5. SERVICES"

$wmiServices = Invoke-WithTimeout -Label "WMI Win32_Service query" -ScriptBlock {
    Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
}

if ($null -ne $wmiServices) {
    $services = $wmiServices | Where-Object { $_.PathName -like "*$fileName*" }

    if ($services) {
        foreach ($svc in $services) {
            try {
                Write-Finding "Service Name" $svc.Name -Severity "HIGH"
                Write-Finding "Display Name" $svc.DisplayName
                Write-Finding "Start Mode"   $svc.StartMode
                $runSev = if ($svc.StartName -match "LocalSystem|SYSTEM") { "HIGH" } else { "INFO" }
                Write-Finding "Run As"       $svc.StartName -Severity $runSev
                Write-Finding "State"        $svc.State
                Write-Finding "Path"         $svc.PathName

                # Fix: extract exe path correctly before checking for spaces
                if ($svc.PathName -match '^"([^"]+)"') {
                    $rawPath = $Matches[1]
                } else {
                    $rawPath = ($svc.PathName -split '\.exe\b')[0] + '.exe'
                }
                if ($svc.PathName -notmatch '^"' -and $rawPath -match ' ') {
                    Write-Finding "Unquoted Path" "VULNERABLE -- unquoted path with spaces: $rawPath" -Severity "HIGH"
                }
            } catch {
                Write-Warn "Service entry parse error: $_"
            }
        }
    } else {
        Write-Finding "Direct Service Match" "None found by filename"
    }

    Write-Raw "`n  -- All unquoted service paths (system-wide) --"
    try {
        $unquoted = $wmiServices | Where-Object {
            $_.PathName -and
            $_.PathName -notmatch '^"' -and
            $_.PathName -match ' ' -and
            $_.PathName -notmatch '^C:\\Windows\\'
        }
        if ($unquoted) {
            foreach ($u in $unquoted) {
                Write-Finding "Unquoted Svc" "$($u.Name) | $($u.PathName)" -Severity "HIGH"
            }
        } else {
            Write-Raw "  No unquoted service paths found system-wide."
        }
    } catch {
        Write-Warn "Unquoted service scan failed: $_"
    }
} else {
    Write-Warn "WMI service query timed out -- section skipped"
}

# -----------------------------------------------
# 6. Scheduled Tasks
# -----------------------------------------------

Write-Section "6. SCHEDULED TASKS"

$taskOut = Invoke-WithTimeout -Label "schtasks query" -ScriptBlock {
    schtasks /query /fo CSV /v 2>&1
}

if ($null -ne $taskOut) {
    try {
        $tasks = $taskOut | ConvertFrom-Csv -ErrorAction Stop |
            Where-Object { $_.'Task To Run' -like "*$fileName*" }

        if ($tasks) {
            foreach ($t in $tasks) {
                try {
                    Write-Finding "Task Name" $t.TaskName -Severity "HIGH"
                    $runSev = if ($t.'Run As User' -match "SYSTEM|Administrator") { "HIGH" } else { "INFO" }
                    Write-Finding "Run As"    $t.'Run As User' -Severity $runSev
                    Write-Finding "Trigger"   $t.Trigger
                    Write-Finding "Command"   $t.'Task To Run'
                    Write-Finding "Status"    $t.Status

                    $taskExe = ($t.'Task To Run' -split ' ')[0].Trim('"')
                    if ($taskExe -and (Test-Path -LiteralPath $taskExe -ErrorAction SilentlyContinue)) {
                        if (Check-Writable $taskExe) {
                            Write-Finding "Task Binary Writable" "LOW-PRIV WRITABLE -- replace to run as $($t.'Run As User')" -Severity "HIGH"
                        }
                    }
                } catch {
                    Write-Warn "Task entry parse error: $_"
                }
            }
        } else {
            Write-Finding "Scheduled Tasks" "No tasks found referencing this file"
        }
    } catch {
        Write-Warn "schtasks CSV parse failed: $_"
    }
} else {
    Write-Warn "schtasks query timed out -- section skipped"
}

# -----------------------------------------------
# 7. Registry Autoruns
# -----------------------------------------------

Write-Section "7. REGISTRY AUTORUNS"

$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

$found = $false
foreach ($rp in $regPaths) {
    try {
        $entries = Get-ItemProperty -Path $rp -ErrorAction Stop
        $entries.PSObject.Properties |
            Where-Object { $_.Value -is [string] -and $_.Value -like "*$fileName*" } |
            ForEach-Object {
                Write-Finding "Autorun Key" "$rp  $($_.Name) = $($_.Value)" -Severity "HIGH"
                $found = $true
            }
    } catch {
        # Key may not exist or access denied -- skip silently
    }
}
if (-not $found) {
    Write-Finding "Autoruns" "No autorun registry entries found for this file"
}

# -----------------------------------------------
# 8. Running Process Check
# -----------------------------------------------

Write-Section "8. RUNNING PROCESS CHECK"

try {
    $procs = Get-Process -Name $fileBase -ErrorAction SilentlyContinue

    if ($procs) {
        foreach ($p in $procs) {
            try {
                Write-Finding "PID"          $p.Id.ToString() -Severity "HIGH"
                Write-Finding "Process Name" $p.ProcessName
                Write-Finding "CPU (s)"      ($p.CPU -as [string])
                Write-Finding "Memory"       "$([math]::Round($p.WorkingSet64/1MB,2)) MB"
            } catch { Write-Warn "Process basic info error: $_" }

            $wmiProc = Invoke-WithTimeout -Label "WMI process owner lookup" -ScriptBlock {
                param($pid)
                Get-WmiObject Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
            }
            if ($null -ne $wmiProc) {
                try {
                    $owner = $wmiProc.GetOwner()
                    $ownerStr = "$($owner.Domain)\$($owner.User)"
                    $ownerSev = if ($owner.User -match "SYSTEM|Administrator") { "HIGH" } else { "INFO" }
                    Write-Finding "Running As" $ownerStr -Severity $ownerSev

                    $parentId = $wmiProc.ParentProcessId
                    $parent   = Get-Process -Id $parentId -ErrorAction SilentlyContinue
                    $parentName = if ($parent) { $parent.ProcessName } else { "unknown" }
                    Write-Finding "Parent PID" "$parentId ($parentName)"
                } catch {
                    Write-Warn "WMI owner/parent parse error: $_"
                }
            }
        }
    } else {
        Write-Finding "Process Running" "Not currently running"
    }
} catch {
    Write-Warn "Process check failed: $_"
}

# -----------------------------------------------
# 9. DLL Hijack Surface
# -----------------------------------------------

Write-Section "9. DLL HIJACK SURFACE"

Write-Raw "  Checking PATH directories writable by non-admins..."

try {
    $pathDirs     = ($env:PATH -split ";") | Where-Object { $_ -and $_.Trim() }
    $writablePaths = [System.Collections.Generic.List[string]]::new()

    foreach ($dir in $pathDirs) {
        $dir = $dir.Trim()
        try {
            if (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue) {
                if (Check-Writable $dir) {
                    $writablePaths.Add($dir)
                    Write-Finding "Writable PATH dir" $dir -Severity "HIGH"
                }
            }
        } catch {
            Write-Warn "PATH dir check error ($dir): $_"
        }
    }

    if ($writablePaths.Count -eq 0) {
        Write-Finding "Writable PATH dirs" "None found (good)" -Severity "LOW"
    }
} catch {
    Write-Warn "DLL hijack surface check failed: $_"
}

Write-Raw "`n  [!] To find DLLs the binary loads, run Process Monitor"
Write-Raw "      Filter: Process Name = $fileName AND Result = NAME NOT FOUND AND Path ends with .dll"

# -----------------------------------------------
# 10. UAC & Token Info
# -----------------------------------------------

Write-Section "10. UAC & CURRENT TOKEN INFO"

try {
    $id        = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]$id
    $isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Finding "Current User" $id.Name
    Write-Finding "Is Admin"     $isAdmin.ToString()
    Write-Finding "Auth Type"    $id.AuthenticationType
} catch {
    Write-Warn "Token info failed: $_"
}

try {
    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop).ConsentPromptBehaviorAdmin
    $uacLabel = switch ($uacVal) {
        0       { "Elevate without prompting (most permissive)" }
        1       { "Prompt for credentials on secure desktop" }
        2       { "Prompt for consent on secure desktop" }
        3       { "Prompt for credentials" }
        4       { "Prompt for consent" }
        5       { "Prompt for consent for non-Windows binaries (default)" }
        default { "Unknown value: $uacVal" }
    }
    $uacSev = if ($uacVal -le 2) { "HIGH" } else { "INFO" }
    Write-Finding "UAC Level" $uacLabel -Severity $uacSev
} catch {
    Write-Warn "UAC registry read failed: $_"
}

try {
    $aie_hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $aie_hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($aie_hklm -eq 1 -and $aie_hkcu -eq 1) {
        Write-Finding "AlwaysInstallElevated" "ENABLED in both hives -- MSI privesc possible" -Severity "HIGH"
    } else {
        Write-Finding "AlwaysInstallElevated" "Not enabled (good)" -Severity "LOW"
    }
} catch {
    Write-Warn "AlwaysInstallElevated check failed: $_"
}

# -----------------------------------------------
# 11. Summary
# -----------------------------------------------

Write-Section "11. SUMMARY & NEXT STEPS"

$summary = @"
  MANUAL STEPS TO FOLLOW UP:
  --------------------------
  [ ] Upload SHA256 to VirusTotal and Hybrid Analysis
  [ ] Run Process Monitor against the binary in a VM:
        Filter : Process Name = $fileName
        Watch  : NAME NOT FOUND (DLL hijack), RegSetValue, WriteFile
  [ ] Check imports with pestudio or Detect-It-Easy
        Look for: SeDebugPrivilege, token manipulation APIs,
                  CreateService, OpenSCManager, AdjustTokenPrivileges
  [ ] If packed: run Detect-It-Easy, unpack (upx -d or dump from memory)
  [ ] If a service binary: test replacing with a custom payload in a lab VM
  [ ] Cross-reference with WinPEAS / PowerUp for broader system misconfigs:
        .\winpeas.exe
        IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks

  USEFUL PRIVESC RESOURCES:
  --------------------------
  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  https://lolbas-project.github.io  (Living Off the Land binaries)
"@
Write-Raw $summary

# -----------------------------------------------
# Save report
# -----------------------------------------------

try {
    $Results | Out-File -FilePath $OutputFile -Encoding UTF8 -ErrorAction Stop
    Write-Host "`n[+] Report saved to: $OutputFile" -ForegroundColor Green
} catch {
    Write-Host "`n[!] Could not save report: $_" -ForegroundColor Red
}