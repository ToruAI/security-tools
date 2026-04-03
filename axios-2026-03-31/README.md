# axios Supply Chain Compromise — Detection Scripts

Detect signs of the **2026-03-31 axios npm supply chain attack** on your machines and CI/CD pipelines.

> **Advisory:** [GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9)
> **Attribution:** Sapphire Sleet / UNC1069 (North Korea, confirmed by Microsoft & Google)

---

## Background

On March 31, 2026, attackers hijacked the npm account of axios maintainer `jasonsaayman` and published malicious versions of one of the most downloaded JavaScript libraries (~100M weekly downloads). The malicious packages contained **SILKBELL** — a dropper that installs **WAVESHAPER.V2**, a cross-platform Remote Access Trojan.

**Exposure window:** ~3 hours (00:21 – 03:25 UTC)
**Estimated downloads during attack:** ~600,000

### Compromised packages

| Package | Version | Notes |
|---|---|---|
| `axios` | `1.14.1` | tagged `latest` |
| `axios` | `0.30.4` | tagged `legacy` |
| `plain-crypto-js` | `4.2.1` | SILKBELL dropper — **should never exist** |
| `plain-crypto-js` | `4.2.0` | Attacker decoy (published 18h before attack) |
| `@shadanai/openclaw` | `2026.3.28-2` to `2026.3.31-2` | Vendors malicious plain-crypto-js |
| `@qqbrowser/openclaw-qbot` | `0.0.130` | Ships compromised axios in node_modules |

**Safe versions:** `axios@1.14.0` (1.x) · `axios@0.30.3` (0.x)

---

## What the scripts detect

| Check | bash (macOS/Linux) | PowerShell (Windows) |
|---|:---:|:---:|
| Compromised axios in lockfiles | ✓ | ✓ |
| package-lock.json / yarn.lock / pnpm-lock.yaml / bun.lock | ✓ | ✓ |
| plain-crypto-js in node_modules | ✓ | ✓ |
| Dropper already executed (self-deleted setup.js) | ✓ | ✓ |
| Secondary compromised packages | ✓ | ✓ |
| SHA256 hash verification of RAT binaries | ✓ | ✓ |
| RAT filesystem artifacts | ✓ | ✓ |
| Active C2 connections (5 domains, 4 IPs) | ✓ | ✓ |
| npm / yarn / pnpm cache hits | ✓ | ✓ |
| Windows Registry persistence (`MicrosoftUpdate`) | — | ✓ |
| `system.bat` + `wt.exe` (Windows RAT) | — | ✓ |
| Scheduled tasks (post-exploitation) | — | ✓ |
| PowerShell history scan | — | ✓ |
| macOS LaunchAgent persistence | ✓ | — |
| Exposure window diagnostics (npm logs + lockfile timestamps) | ✓ | ✓ |
| bun cache hits | — | ✓ |
| JSON output (CI-friendly) | ✓ | ✓ |

---

## Usage

### macOS / Linux

```bash
# Scan current directory
./axios-scan.sh

# Scan specific path (recursive)
./axios-scan.sh /path/to/repos

# CI-friendly JSON output
./axios-scan.sh --json /path/to/repos

# No color (for logs)
./axios-scan.sh --no-color
```

### Windows (PowerShell)

```powershell
# Scan current directory
.\axios-scan.ps1

# Scan specific path
.\axios-scan.ps1 -ScanDir C:\repos

# JSON output
.\axios-scan.ps1 -Json

# If execution policy blocks you
powershell -ExecutionPolicy Bypass -File axios-scan.ps1
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — nothing found |
| `1` | Suspicious — compromised version in lockfile or cache (shows exposure window diagnostics) |
| `2` | Compromised — RAT artifacts or active C2 connection detected |

### CI/CD integration

```yaml
# GitHub Actions example
- name: Check for axios compromise
  run: |
    chmod +x ./axios-scan.sh
    ./axios-scan.sh --no-color .
```

---

## If you find something

**Exit code 1 (Suspicious):**
```bash
npm install axios@1.14.0        # downgrade (or 0.30.3 for 0.x)
rm -rf node_modules/plain-crypto-js
npm cache clean --force
rm -rf node_modules && npm install
```
Check if `npm install` ran during the exposure window: **2026-03-31, 00:21 – 03:25 UTC**

**Exit code 2 (Compromised):**
1. **Isolate the machine from the network immediately**
2. Rotate all credentials: npm tokens, SSH keys, cloud credentials (AWS/GCP/Azure), CI/CD secrets, .env files
3. Preserve disk image before cleanup (for forensics)
4. On Windows, remove persistence:
```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftUpdate"
Remove-Item "$env:ProgramData\wt.exe", "$env:ProgramData\system.bat" -Force
```

---

## IOCs

**C2 domains:** `sfrclak.com` · `calltan.com` · `callnrwise.com` · `hopex.pro` · `coretrade.app`
**C2 IPs:** `142.11.206.73` · `23.254.167.216` · `45.61.128.54` · `144.172.89.231`
**C2 port:** `8000`
**User-Agent:** `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`

**RAT artifact SHA256:**

| Platform | Path | SHA256 |
|---|---|---|
| Dropper | `node_modules/plain-crypto-js/setup.js` | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |
| macOS | `/Library/Caches/com.apple.act.mond` | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| Linux | `/tmp/ld.py` | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |
| Windows | `%PROGRAMDATA%\wt.exe` | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` |

---

## Sources

- [Elastic Security Labs — Inside the Axios supply chain compromise](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)
- [Microsoft Security Blog — Mitigating the Axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- [Google Cloud — North Korea-Nexus Threat Actor Targets Axios](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package)
- [StepSecurity — axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Datadog Security Labs — Compromised axios npm package](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- [GitHub Advisory GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9)
- [YARA/Sigma/Suricata rules — N3mes1s](https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6)

---

*Built by [ToruAI](https://toruai.com)*
