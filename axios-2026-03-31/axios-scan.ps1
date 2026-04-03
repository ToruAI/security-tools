# =============================================================================
# axios-scan.ps1 — npm Supply Chain Compromise Detector (Windows)
# =============================================================================
#
# Detects signs of the axios npm supply chain attack (2026-03-31)
#
#   Attack summary:
#     Attacker hijacked npm account 'jasonsaayman' (axios maintainer) and
#     published malicious versions containing SILKBELL dropper, which installs
#     WAVESHAPER.V2 RAT. Windows variant uses PowerShell + Registry persistence.
#     Exposure window: ~3 hours (00:21 – 03:25 UTC, March 31 2026).
#
#   Attribution: Sapphire Sleet / UNC1069 / BlueNoroff (DPRK)
#   GitHub Advisory: GHSA-fw8c-xr5c-95f9
#
#   Windows-specific artifacts:
#     %PROGRAMDATA%\wt.exe                          (disguised as Windows Terminal)
#     %PROGRAMDATA%\system.bat                      (persistence launcher)
#     HKCU:\...\CurrentVersion\Run\MicrosoftUpdate  (Registry Run key)
#     %TEMP%\6202033.ps1                            (stage-1 dropper, self-deletes)
#     %TEMP%\6202033.vbs                            (VBS wrapper, self-deletes)
#
#   WAVESHAPER.V2 SHA256:
#     Windows binary:  617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
#     Dropper setup.js: e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
#
#   C2 infrastructure:
#     Primary:   sfrclak.com / 142.11.206.73:8000
#     Backup:    calltan.com, callnrwise.com, hopex.pro, coretrade.app
#     Backup IPs: 23.254.167.216, 45.61.128.54, 144.172.89.231
#     User-Agent: "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
#
# Usage:
#   .\axios-scan.ps1                          # scan current directory
#   .\axios-scan.ps1 -ScanDir C:\repos        # scan specific directory
#   .\axios-scan.ps1 -Json                    # JSON output
#   .\axios-scan.ps1 -Verbose                 # show each scanned file
#   .\axios-scan.ps1 -NoColor                 # plain output
#
# Exit codes: 0=clean  1=suspicious  2=compromised
#
# Run as: PowerShell -ExecutionPolicy Bypass -File axios-scan.ps1
# =============================================================================

[CmdletBinding()]
param(
    [string]$ScanDir = ".",
    [switch]$Json,
    [switch]$NoColor,
    [switch]$Help
)

$VERSION = "1.1.0"

if ($Help) {
    Write-Host "Usage: .\axios-scan.ps1 [-ScanDir <path>] [-Json] [-NoColor] [-Verbose] [-Help]"
    Write-Host "Exit codes: 0=clean  1=suspicious  2=compromised"
    exit 0
}

# --- State -------------------------------------------------------------------
$script:ExitCode = 0
$script:FindingsPackages  = [System.Collections.Generic.List[string]]::new()
$script:FindingsModules   = [System.Collections.Generic.List[string]]::new()
$script:FindingsArtifacts = [System.Collections.Generic.List[string]]::new()
$script:FindingsNetwork   = [System.Collections.Generic.List[string]]::new()
$script:FindingsCache     = [System.Collections.Generic.List[string]]::new()

# --- Output helpers ----------------------------------------------------------
function Write-Stderr { param([string]$msg)
    [Console]::Error.WriteLine($msg)
}
function Write-Header { param([string]$msg)
    if (-not $Json) { Write-Host "`n$msg" -ForegroundColor Cyan }
    else { Write-Stderr "`n$msg" }
}
function Write-Ok     { param([string]$msg)
    $line = "  [OK]  $msg"
    if ($Json) { Write-Stderr $line } elseif (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "+" -ForegroundColor Green -NoNewline; Write-Host "  $msg" } else { Write-Host $line }
}
function Write-Warn   { param([string]$msg)
    $line = "  [WARN] $msg"
    if ($Json) { Write-Stderr $line } elseif (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "!" -ForegroundColor Yellow -NoNewline; Write-Host "  $msg" } else { Write-Host $line }
}
function Write-Danger { param([string]$msg)
    $line = "  [!!!] $msg"
    if ($Json) { Write-Stderr $line } elseif (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "X" -ForegroundColor Red -NoNewline; Write-Host "  $msg" -ForegroundColor Red } else { Write-Host $line }
}
function Write-Info   { param([string]$msg)
    $line = "      $msg"
    if ($Json) { Write-Stderr $line } else { Write-Host $line -ForegroundColor DarkGray }
}

function Get-SHA256 { param([string]$path)
    if (Test-Path $path -PathType Leaf) {
        try { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLower() } catch { "" }
    } else { "" }
}

# --- Phase 1: Package lockfiles ----------------------------------------------
function Scan-Lockfiles {
    Write-Header "Phase 1/4 — Package lockfiles"

    $lockfileNames = @("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
    $excludeDirs   = @("node_modules", ".git", ".cache")

    $lockfiles = Get-ChildItem -Path $ScanDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $lockfileNames -contains $_.Name -and
            -not ($_.FullName -split '\\' | Where-Object { $excludeDirs -contains $_ })
        }

    if (-not $lockfiles) {
        Write-Info "No lockfiles found under $ScanDir"
        return
    }

    $count = 0
    foreach ($lockfile in $lockfiles) {
        $count++
        if ($VerbosePreference -ne 'SilentlyContinue') { Write-Info "Scanning: $($lockfile.FullName)" }
        $content = Get-Content $lockfile.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        # --- Compromised axios versions ---
        # Handles package-lock.json (JSON), yarn.lock (key@ver:), pnpm-lock.yaml (YAML)
        if ($content -match 'axios') {
            $badVer = $null
            $lines = $content -split "`n"
            $inAxios = $false; $linesSince = 0
            foreach ($line in $lines) {
                if ($line -match '["/]axios"?\s*[:{]') {
                    $inAxios = $true; $linesSince = 0
                }
                if ($inAxios) {
                    $linesSince++
                    if ($line -match '"?version"?\s*[:=]\s*"?(1\.14\.1|0\.30\.4)"?') {
                        $badVer = $Matches[1]; $inAxios = $false; break
                    }
                    if ($linesSince -gt 15) { $inAxios = $false }
                }
            }
            if ($badVer) {
                Write-Danger "COMPROMISED axios@$badVer in: $($lockfile.FullName)"
                $script:FindingsPackages.Add("$($lockfile.FullName): axios@$badVer")
                if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            }
        }

        # --- plain-crypto-js ---
        if ($content -match 'plain-crypto-js') {
            $pcjsBlock = [regex]::Match($content, '"(node_modules/)?plain-crypto-js"[^{]*\{[^}]+\}')
            if ($pcjsBlock.Success -and $pcjsBlock.Value -match '"version"\s*:\s*"([^"]+)"') {
                $pcVer = $Matches[1]
            } else { $pcVer = "unknown" }

            if ($pcVer -eq "4.2.1") {
                Write-Danger "RAT DROPPER (SILKBELL): plain-crypto-js@4.2.1 in: $($lockfile.FullName)"
                $script:FindingsPackages.Add("$($lockfile.FullName): plain-crypto-js@4.2.1 (SILKBELL)")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            } elseif ($pcVer -eq "4.2.0") {
                Write-Warn "SUSPICIOUS: plain-crypto-js@4.2.0 (attacker decoy) in: $($lockfile.FullName)"
                $script:FindingsPackages.Add("$($lockfile.FullName): plain-crypto-js@4.2.0 (decoy)")
                if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            } else {
                Write-Danger "plain-crypto-js found (any version suspicious): $($lockfile.FullName)"
                $script:FindingsPackages.Add("$($lockfile.FullName): plain-crypto-js@$pcVer")
                if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            }
        }

        # --- @shadanai/openclaw ---
        if ($content -match '@shadanai/openclaw') {
            Write-Danger "COMPROMISED package: @shadanai/openclaw in: $($lockfile.FullName)"
            Write-Danger "  This package vendors malicious plain-crypto-js"
            $script:FindingsPackages.Add("$($lockfile.FullName): @shadanai/openclaw")
            if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
        }

        # --- @qqbrowser/openclaw-qbot@0.0.130 ---
        if ($content -match 'openclaw-qbot') {
            $qbVer = $null
            $inQbot = $false; $qbLines = 0
            foreach ($line in ($content -split "`n")) {
                if ($line -match 'openclaw-qbot') { $inQbot = $true; $qbLines = 0 }
                if ($inQbot) {
                    $qbLines++
                    if ($line -match '"version"\s*:\s*"([^"]+)"') { $qbVer = $Matches[1]; $inQbot = $false; break }
                    if ($qbLines -gt 15) { $inQbot = $false }
                }
            }
            if ($qbVer -eq "0.0.130") {
                Write-Danger "COMPROMISED: @qqbrowser/openclaw-qbot@0.0.130 in: $($lockfile.FullName)"
                $script:FindingsPackages.Add("$($lockfile.FullName): @qqbrowser/openclaw-qbot@0.0.130")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            }
        }
    }

    if ($script:FindingsPackages.Count -eq 0) {
        Write-Ok "Scanned $count lockfile(s) — no compromised packages found"
    }
}

# --- Phase 2: node_modules ---------------------------------------------------
function Scan-NodeModules {
    Write-Header "Phase 2/4 — node_modules"

    $nmDirs = Get-ChildItem -Path $ScanDir -Recurse -Directory -Filter "node_modules" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch 'node_modules.+node_modules' }

    if (-not $nmDirs) {
        Write-Info "No node_modules directories found"
        return
    }

    $count = 0
    foreach ($nm in $nmDirs) {
        $count++
        if ($VerbosePreference -ne 'SilentlyContinue') { Write-Info "Checking: $($nm.FullName)" }

        # --- plain-crypto-js ---
        $pcjsDir = Join-Path $nm.FullName "plain-crypto-js"
        if (Test-Path $pcjsDir -PathType Container) {
            $pcVer = ""
            $pkgJson = Join-Path $pcjsDir "package.json"
            $setupJs = Join-Path $pcjsDir "setup.js"
            if (Test-Path $pkgJson) {
                $pkgContent = Get-Content $pkgJson -Raw -ErrorAction SilentlyContinue
                if ($pkgContent -match '"version"\s*:\s*"([^"]+)"') { $pcVer = $Matches[1] }
            }
            $hasSetup = Test-Path $setupJs

            if ($hasSetup) {
                Write-Danger "SILKBELL DROPPER LOADED (not yet executed): $pcjsDir@$pcVer"
                Write-Danger "  setup.js present — will execute on next npm install"
                $script:FindingsModules.Add("$pcjsDir@$pcVer (setup.js present)")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            } elseif ($pcVer -eq "4.2.1") {
                Write-Danger "DROPPER ALREADY EXECUTED: $pcjsDir@4.2.1"
                Write-Danger "  setup.js gone — SILKBELL ran and self-deleted. System was exposed."
                $script:FindingsModules.Add("$pcjsDir@4.2.1 (dropper ran, self-deleted)")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            } else {
                Write-Warn "SUSPICIOUS: plain-crypto-js@$pcVer in $($nm.FullName)"
                $script:FindingsModules.Add("$pcjsDir@$pcVer (suspicious)")
                if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            }
        }

        # --- axios version ---
        $axiosPkg = Join-Path $nm.FullName "axios\package.json"
        if (Test-Path $axiosPkg) {
            $axContent = Get-Content $axiosPkg -Raw -ErrorAction SilentlyContinue
            if ($axContent -match '"version"\s*:\s*"([^"]+)"') {
                $axVer = $Matches[1]
                if ($axVer -eq "1.14.1" -or $axVer -eq "0.30.4") {
                    Write-Danger "COMPROMISED axios@$axVer installed: $($nm.FullName)"
                    $script:FindingsModules.Add("$($nm.FullName)\axios@$axVer")
                    if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
                }
            }
        }

        # --- @shadanai ---
        $shadanaiDir = Join-Path $nm.FullName "@shadanai"
        if (Test-Path $shadanaiDir -PathType Container) {
            $ocDirs = Get-ChildItem $shadanaiDir -Directory -Filter "openclaw*" -ErrorAction SilentlyContinue
            if ($ocDirs) {
                Write-Danger "COMPROMISED @shadanai/openclaw installed: $shadanaiDir"
                $script:FindingsModules.Add("$shadanaiDir\openclaw")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            }
        }
    }

    if ($script:FindingsModules.Count -eq 0) {
        Write-Ok "Checked $count node_modules — no malicious packages installed"
    }
}

# --- Phase 3: Windows-specific RAT artifacts ---------------------------------
function Scan-Artifacts {
    Write-Header "Phase 3/4 — Filesystem & Registry artifacts (RAT)"

    $KNOWN_HASHES = @{
        "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101" = "Windows WAVESHAPER.V2"
    }
    $script:artifactsFound = 0

    function Check-Artifact {
        param([string]$path, [string]$label, [string]$expectedSha = "")
        if (Test-Path $path) {
            Write-Danger "RAT ARTIFACT: $label"
            Write-Danger "  Path: $path"
            if ($expectedSha -and (Test-Path $path -PathType Leaf)) {
                $actual = Get-SHA256 $path
                if ($actual -eq $expectedSha) {
                    Write-Danger "  SHA256: $actual  [CONFIRMED RAT BINARY]"
                } else {
                    Write-Warn   "  SHA256: $actual  [hash mismatch — verify manually]"
                }
            }
            try {
                $item = Get-Item $path -ErrorAction SilentlyContinue
                if ($item) {
                    Write-Danger "  Size: $([Math]::Round($item.Length/1KB, 1))KB  Modified: $($item.LastWriteTime)"
                }
            } catch {}
            $script:FindingsArtifacts.Add($path)
            if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            $script:artifactsFound++
        }
    }

    # Windows RAT binary (disguised as Windows Terminal)
    Check-Artifact `
        "$env:ProgramData\wt.exe" `
        "WAVESHAPER.V2 binary (disguised as Windows Terminal)" `
        "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"

    # Persistence batch file
    Check-Artifact "$env:ProgramData\system.bat" "RAT persistence launcher (system.bat)"

    # Temp stage-1 files (self-deleting but worth checking)
    Check-Artifact "$env:TEMP\6202033.ps1" "RAT stage-1 PowerShell dropper (temp)"
    Check-Artifact "$env:TEMP\6202033.vbs" "RAT stage-1 VBScript wrapper (temp)"

    # --- Registry persistence ---
    $regPath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regKey   = "MicrosoftUpdate"
    try {
        $regVal = Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue
        if ($regVal) {
            Write-Danger "REGISTRY PERSISTENCE: $regPath\$regKey"
            Write-Danger "  Value: $($regVal.$regKey)"
            $script:FindingsArtifacts.Add("Registry: $regPath\$regKey = $($regVal.$regKey)")
            if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            $script:artifactsFound++
        }
    } catch {}

    # Also check HKLM Run (if attacker escalated privileges)
    $regPathLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    try {
        $regValLM = Get-ItemProperty -Path $regPathLM -Name $regKey -ErrorAction SilentlyContinue
        if ($regValLM) {
            Write-Danger "REGISTRY PERSISTENCE (SYSTEM-LEVEL): $regPathLM\$regKey"
            Write-Danger "  Value: $($regValLM.$regKey)"
            $script:FindingsArtifacts.Add("Registry HKLM: $regPathLM\$regKey")
            if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
            $script:artifactsFound++
        }
    } catch {}

    # --- Scheduled tasks (attacker could deploy via runscript) ---
    try {
        $suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -match "Microsoft|Update|axios" -and $_.Author -notmatch "Microsoft" } |
            Where-Object {
                ($_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).LastRunTime -gt (Get-Date).AddDays(-7)
            }
        foreach ($task in $suspiciousTasks) {
            Write-Warn "SUSPICIOUS scheduled task: $($task.TaskPath)$($task.TaskName)"
            $script:FindingsArtifacts.Add("Scheduled task: $($task.TaskName)")
            if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            $script:artifactsFound++
        }
    } catch {}

    if ($script:artifactsFound -eq 0 -and $script:FindingsArtifacts.Count -eq 0) {
        Write-Ok "No RAT artifacts or persistence found"
    }
}

# --- Phase 4: Network IOCs ---------------------------------------------------
function Scan-Network {
    Write-Header "Phase 4/4 — Network connections & indicators"

    $C2_DOMAINS = @("sfrclak.com", "calltan.com", "callnrwise.com", "hopex.pro", "coretrade.app")
    $C2_IPS     = @("142.11.206.73", "23.254.167.216", "45.61.128.54", "144.172.89.231")
    $networkHits = 0

    # --- Active TCP connections ---
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($ip in $C2_IPS) {
            $hits = $connections | Where-Object { $_.RemoteAddress -eq $ip }
            foreach ($hit in $hits) {
                Write-Danger "ACTIVE C2 CONNECTION: ${ip}:$($hit.RemotePort)"
                Write-Danger "  Local: $($hit.LocalAddress):$($hit.LocalPort)  PID: $($hit.OwningProcess)"
                try {
                    $proc = Get-Process -Id $hit.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) { Write-Danger "  Process: $($proc.Name) ($($proc.MainModule.FileName))" }
                } catch {}
                $script:FindingsNetwork.Add("Active connection to ${ip}:$($hit.RemotePort) (PID $($hit.OwningProcess))")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
                $networkHits++
            }
        }
    } catch {}

    # --- DNS: do C2 domains resolve? ---
    foreach ($domain in $C2_DOMAINS) {
        try {
            $dns = Resolve-DnsName $domain -ErrorAction SilentlyContinue -Type A
            if ($dns) {
                $ips = ($dns | Where-Object { $_.Type -eq "A" }).IPAddress -join ", "
                Write-Warn "C2 domain still resolves: $domain -> $ips"
            }
        } catch {}
    }

    # --- hosts file poisoning ---
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
        foreach ($domain in $C2_DOMAINS) {
            if ($hostsContent | Where-Object { $_ -match [regex]::Escape($domain) }) {
                Write-Danger "C2 domain in hosts file: $domain"
                $script:FindingsNetwork.Add("hosts file: $domain")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
                $networkHits++
            }
        }
        foreach ($ip in $C2_IPS) {
            if ($hostsContent | Where-Object { $_ -match [regex]::Escape($ip) }) {
                Write-Danger "C2 IP in hosts file: $ip"
                $script:FindingsNetwork.Add("hosts file: $ip")
                if ($script:ExitCode -lt 2) { $script:ExitCode = 2 }
                $networkHits++
            }
        }
    }

    # --- PowerShell history (post-compromise commands) ---
    $psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $psHistory) {
        $histContent = Get-Content $psHistory -ErrorAction SilentlyContinue
        $c2Hits = $histContent | Where-Object { $_ -match "sfrclak|plain-crypto-js|6202033|wt\.exe" }
        foreach ($line in $c2Hits) {
            Write-Warn "C2 indicator in PowerShell history: $line"
            $script:FindingsNetwork.Add("PS history: $line")
            if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
        }
    }

    # --- Package manager caches ---
    # npm: honour npm_config_cache env var, fall back to default
    $npmCacheRoot = if ($env:npm_config_cache) { $env:npm_config_cache } else { "$env:AppData\npm-cache" }
    $npmCacache = Join-Path $npmCacheRoot "_cacache"
    if (Test-Path $npmCacache) {
        $badCache = Get-ChildItem $npmCacache -Recurse -Filter "*.json" -ErrorAction SilentlyContinue |
            Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match '"plain-crypto-js"' }
        if ($badCache) {
            Write-Warn "Malicious package evidence in npm cache ($npmCacache)"
            Write-Warn "  Run: npm cache clean --force"
            foreach ($cf in $badCache) {
                $script:FindingsCache.Add("npm cache: $($cf.FullName)")
            }
            if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
        }
    }

    # pnpm: honour PNPM_HOME or pnpm store path
    $pnpmStore = $null
    try { $pnpmStore = & pnpm store path 2>$null } catch {}
    if (-not $pnpmStore -and $env:PNPM_HOME) { $pnpmStore = Join-Path $env:PNPM_HOME "store" }
    if (-not $pnpmStore) { $pnpmStore = Join-Path $env:LOCALAPPDATA "pnpm-store" }
    if (Test-Path $pnpmStore -ErrorAction SilentlyContinue) {
        $badPnpm = Get-ChildItem $pnpmStore -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
            Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match '"plain-crypto-js"' }
        if ($badPnpm) {
            Write-Warn "Malicious package evidence in pnpm store ($pnpmStore)"
            Write-Warn "  Run: pnpm store prune"
            foreach ($cf in $badPnpm) {
                $script:FindingsCache.Add("pnpm store: $($cf.FullName)")
            }
            if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
        }
    }

    # yarn (v1 + v2+/berry)
    $yarnCacheDirs = @()
    try { $yarnClassic = & yarn cache dir 2>$null; if ($yarnClassic) { $yarnCacheDirs += $yarnClassic } } catch {}
    $yarnBerry = Join-Path $env:LOCALAPPDATA "Yarn\Berry\cache"
    if (Test-Path $yarnBerry) { $yarnCacheDirs += $yarnBerry }
    foreach ($yarnDir in $yarnCacheDirs) {
        if (Test-Path $yarnDir) {
            $badYarn = Get-ChildItem $yarnDir -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'plain-crypto-js' }
            if ($badYarn) {
                Write-Warn "Malicious package evidence in yarn cache ($yarnDir)"
                Write-Warn "  Run: yarn cache clean"
                foreach ($cf in $badYarn) {
                    $script:FindingsCache.Add("yarn cache: $($cf.FullName)")
                }
                if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
            }
        }
    }

    # bun
    $bunCache = if ($env:BUN_INSTALL) { Join-Path $env:BUN_INSTALL "install\cache" } else { "$env:USERPROFILE\.bun\install\cache" }
    if (Test-Path $bunCache -ErrorAction SilentlyContinue) {
        $badBun = Get-ChildItem $bunCache -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'plain-crypto-js' }
        if (-not $badBun) {
            # also check content-addressed cache for the package name
            $badBun = Get-ChildItem $bunCache -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
                Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match '"plain-crypto-js"' }
        }
        if ($badBun) {
            Write-Warn "Malicious package evidence in bun cache ($bunCache)"
            Write-Warn "  Run: bun pm cache rm"
            foreach ($cf in $badBun) {
                $script:FindingsCache.Add("bun cache: $($cf.FullName)")
            }
            if ($script:ExitCode -lt 1) { $script:ExitCode = 1 }
        }
    }

    if ($networkHits -eq 0 -and $script:FindingsNetwork.Count -eq 0 -and $script:FindingsCache.Count -eq 0) {
        Write-Ok "No active C2 connections or cache hits detected"
    }
}

# --- JSON output -------------------------------------------------------------
function Output-Json {
    $status = @{0="CLEAN"; 1="SUSPICIOUS"; 2="COMPROMISED"}[$script:ExitCode]

    $obj = [ordered]@{
        scanner   = "axios-scan.ps1"
        version   = $VERSION
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        platform  = "windows"
        scan_dir  = (Resolve-Path $ScanDir).Path
        status    = $status
        exit_code = $script:ExitCode
        advisory  = "GHSA-fw8c-xr5c-95f9"
        findings  = [ordered]@{
            lockfiles    = @($script:FindingsPackages)
            node_modules = @($script:FindingsModules)
            filesystem   = @($script:FindingsArtifacts)
            network      = @($script:FindingsNetwork)
            cache        = @($script:FindingsCache)
        }
    }
    ConvertTo-Json $obj -Depth 5
}

# --- Exposure window diagnostics ---------------------------------------------
function Show-ExposureCheck {
    # Exposure window: 2026-03-31 00:21 – 03:25 UTC
    $windowStart = [DateTime]::Parse("2026-03-31T00:21:00Z").ToUniversalTime()
    $windowEnd   = [DateTime]::Parse("2026-03-31T03:25:00Z").ToUniversalTime()

    Write-Host "  Exposure window diagnostics:" -ForegroundColor Cyan

    # 1. npm install logs during the window
    $npmLogsRoot = if ($env:npm_config_cache) { $env:npm_config_cache } else { "$env:APPDATA\npm-cache" }
    $npmLogsDir = Join-Path $npmLogsRoot "_logs"
    if (Test-Path $npmLogsDir) {
        $windowLogs = Get-ChildItem $npmLogsDir -Filter "*.log" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $windowStart -and $_.LastWriteTimeUtc -le $windowEnd }
        if ($windowLogs) {
            if (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "!" -ForegroundColor Yellow -NoNewline }
            else { Write-Host "  [!]" -NoNewline }
            Write-Host "  npm logs DURING exposure window:"
            foreach ($log in $windowLogs) {
                Write-Host "       $($log.Name)  $($log.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Yellow
            }
        } else {
            if (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "+" -ForegroundColor Green -NoNewline }
            else { Write-Host "  [OK]" -NoNewline }
            Write-Host "  No npm logs found during exposure window"
        }
    } else {
        Write-Host "      npm log directory not found ($npmLogsDir)" -ForegroundColor DarkGray
    }

    # 2. Lockfile last-modified timestamps
    $lockfileNames = @("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
    $lockfiles = Get-ChildItem -Path $ScanDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $lockfileNames -contains $_.Name -and $_.FullName -notmatch '[\\/]node_modules[\\/]' }
    if ($lockfiles) {
        foreach ($lf in $lockfiles) {
            $modUtc = $lf.LastWriteTimeUtc
            $ts = $modUtc.ToString("yyyy-MM-dd HH:mm:ss")
            $inWindow = ($modUtc -ge $windowStart -and $modUtc -le $windowEnd)
            if ($inWindow) {
                if (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "!" -ForegroundColor Red -NoNewline }
                else { Write-Host "  [!]" -NoNewline }
                Write-Host "  $($lf.FullName)" -NoNewline
                Write-Host "  modified $ts UTC" -ForegroundColor Red -NoNewline
                Write-Host "  <-- INSIDE exposure window" -ForegroundColor Red
            } else {
                if (-not $NoColor) { Write-Host "  " -NoNewline; Write-Host "+" -ForegroundColor Green -NoNewline }
                else { Write-Host "  [OK]" -NoNewline }
                Write-Host "  $($lf.FullName)" -NoNewline
                Write-Host "  modified $ts UTC" -ForegroundColor DarkGray -NoNewline
                Write-Host "  (outside window)"
            }
        }
    }
    Write-Host ""
}

# --- Summary -----------------------------------------------------------------
function Print-Summary {
    $total = $script:FindingsPackages.Count + $script:FindingsModules.Count +
             $script:FindingsArtifacts.Count + $script:FindingsNetwork.Count +
             $script:FindingsCache.Count

    Write-Host ""
    Write-Host ("=" * 52)

    switch ($script:ExitCode) {
        0 {
            if (-not $NoColor) { Write-Host "  RESULT: CLEAN" -ForegroundColor Green }
            else { Write-Host "  RESULT: CLEAN" }
            Write-Host "  No signs of the axios supply chain compromise detected."
        }
        1 {
            if (-not $NoColor) { Write-Host "  RESULT: SUSPICIOUS — $total finding(s)" -ForegroundColor Yellow }
            else { Write-Host "  RESULT: SUSPICIOUS — $total finding(s)" }
            Write-Host ""
            Write-Host "  Compromised axios version found in lockfile/cache."
            Write-Host ""
            Write-Host "  Exposure window: 2026-03-31  00:21 - 03:25 UTC" -ForegroundColor DarkGray
            Write-Host ""
            Show-ExposureCheck
            Write-Host ""
            Write-Host "  Remediation:"
            Write-Host "  1. Downgrade:  npm install axios@1.14.0  (or 0.30.3 for 0.x)"
            Write-Host "  2. Remove:     Remove-Item node_modules\plain-crypto-js -Recurse"
            Write-Host "  3. Clean:      npm cache clean --force  (or pnpm store prune / yarn cache clean / bun pm cache rm)"
            Write-Host "  4. Reinstall:  Remove-Item node_modules -Recurse; npm install"
            Write-Host "  5. Audit CI:   check pipeline logs from exposure window"
        }
        2 {
            if (-not $NoColor) { Write-Host "  RESULT: COMPROMISED — $total finding(s)" -ForegroundColor Red }
            else { Write-Host "  RESULT: COMPROMISED — $total finding(s)" }
            Write-Host ""
            if (-not $NoColor) { Write-Host "  WAVESHAPER.V2 RAT artifacts detected. Assume full compromise." -ForegroundColor Red }
            else { Write-Host "  WAVESHAPER.V2 RAT artifacts detected. Assume full compromise." }
            Write-Host ""
            Show-ExposureCheck
            Write-Host ""
            Write-Host "  Immediate actions:"
            Write-Host "  1. ISOLATE this machine from the network NOW" -ForegroundColor Red
            Write-Host "  2. Rotate ALL credentials:"
            Write-Host "     - npm tokens    (%USERPROFILE%\.npmrc)"
            Write-Host "     - SSH keys      (%USERPROFILE%\.ssh\)"
            Write-Host "     - Cloud creds   (%USERPROFILE%\.aws\, Azure, GCP)"
            Write-Host "     - CI/CD secrets (GitHub Actions, GitLab CI, etc.)"
            Write-Host "     - .env files    (database passwords, API keys)"
            Write-Host "  3. Preserve disk image before cleanup (forensics)"
            Write-Host "  4. Remove persistence:"
            Write-Host "     Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name MicrosoftUpdate"
            Write-Host "     Remove-Item `$env:ProgramData\wt.exe, `$env:ProgramData\system.bat"
            Write-Host "  5. Report to your security team"
            Write-Host "  6. Advisory: GHSA-fw8c-xr5c-95f9"
        }
    }

    Write-Host ("=" * 52)
    Write-Host ""
}

# --- Entrypoint --------------------------------------------------------------
if (-not $Json) {
    Write-Host "axios-scan.ps1 v$VERSION  |  WAVESHAPER.V2 / axios Supply Chain Detector" -ForegroundColor Cyan
    Write-Host "Scanning: $(Resolve-Path $ScanDir)"
    Write-Host "Platform: windows  |  Advisory: GHSA-fw8c-xr5c-95f9  |  $(Get-Date -Format u)"
}

Scan-Lockfiles
Scan-NodeModules
Scan-Artifacts
Scan-Network

if ($Json) {
    Output-Json
} else {
    Print-Summary
}

exit $script:ExitCode
