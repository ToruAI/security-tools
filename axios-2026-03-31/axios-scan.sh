#!/usr/bin/env bash
# =============================================================================
# axios-scan.sh — npm Supply Chain Compromise Detector
# =============================================================================
#
# Detects signs of the axios npm supply chain attack (2026-03-31)
#
#   Attack summary:
#     Attacker hijacked npm account 'jasonsaayman' (axios maintainer) and
#     published malicious versions containing a RAT dropper (SILKBELL).
#     The dropper installs WAVESHAPER.V2, a cross-platform RAT, via a
#     postinstall script in a hidden dependency (plain-crypto-js).
#     Exposure window: ~3 hours (00:21 – 03:25 UTC, March 31 2026).
#
#   Attribution: Sapphire Sleet / UNC1069 / BlueNoroff (DPRK, MSFT + Google)
#   GitHub Advisory: GHSA-fw8c-xr5c-95f9
#
#   Compromised packages:
#     axios@1.14.1              (tagged 'latest')
#     axios@0.30.4              (tagged 'legacy')
#     plain-crypto-js@4.2.0     (clean decoy — presence is suspicious)
#     plain-crypto-js@4.2.1     (SILKBELL dropper — critical)
#     @shadanai/openclaw@2026.3.28-2 / 2026.3.28-3 / 2026.3.31-1 / 2026.3.31-2
#     @qqbrowser/openclaw-qbot@0.0.130
#
#   Safe versions:
#     axios@1.x  →  1.14.0
#     axios@0.x  →  0.30.3
#
#   WAVESHAPER.V2 RAT SHA256:
#     Dropper (setup.js):  e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
#     macOS  binary:       92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a
#     Linux  script:       fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
#     Linux  script (alt): 6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7
#     Windows binary:      617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
#
#   C2 infrastructure:
#     Primary:  sfrclak.com  /  142.11.206.73:8000
#     Domains:  calltan.com, callnrwise.com, hopex.pro, coretrade.app
#     Backup IPs: 23.254.167.216, 45.61.128.54, 144.172.89.231
#     Campaign ID: /6202033 (reversed date: 3-30-2026)
#     User-Agent: "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
#
#   Key research sources:
#     https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
#     https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
#     https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
#     https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
#     https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/
#     https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6
#
# Usage:
#   ./axios-scan.sh                  # scan current directory
#   ./axios-scan.sh /path/to/repos   # scan specific directory (recursive)
#   ./axios-scan.sh --no-color       # plain output (for pipes/logs)
#   ./axios-scan.sh --json           # JSON output (phases printed to stderr)
#   ./axios-scan.sh --verbose        # show every file scanned
#   ./axios-scan.sh --help
#
# Exit codes:
#   0  CLEAN       — nothing found
#   1  SUSPICIOUS  — compromised package found in lockfile/cache
#   2  COMPROMISED — RAT artifacts, active process, or C2 traffic detected
#
# =============================================================================

set -uo pipefail

VERSION="1.1.0"
SCRIPT_NAME="$(basename "$0")"

# --- Defaults ----------------------------------------------------------------
SCAN_DIR="."
USE_COLOR=true
JSON_OUTPUT=false
VERBOSE=false

# --- State -------------------------------------------------------------------
FINDINGS_PACKAGES=()
FINDINGS_MODULES=()
FINDINGS_ARTIFACTS=()
FINDINGS_NETWORK=()
FINDINGS_CACHE=()

EXIT_CODE=0

# --- Colors ------------------------------------------------------------------
setup_colors() {
  if $USE_COLOR && [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
  else
    RED='' YELLOW='' GREEN='' CYAN='' BOLD='' DIM='' RESET=''
  fi
}

# --- Output helpers ----------------------------------------------------------
_out()   { $JSON_OUTPUT && echo -e "$*" >&2 || echo -e "$*"; }
header() { _out "\n${BOLD}${CYAN}$*${RESET}"; }
ok()     { _out "  ${GREEN}✓${RESET}  $*"; }
warn()   { _out "  ${YELLOW}⚠${RESET}  $*"; }
danger() { _out "  ${RED}✗${RESET}  ${RED}$*${RESET}"; }
info()   { _out "  ${DIM}·${RESET}  $*"; }

# --- Argument parsing --------------------------------------------------------
usage() {
  echo "Usage: $SCRIPT_NAME [DIRECTORY] [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --no-color    Disable color output"
  echo "  --json        Output JSON report (phases go to stderr)"
  echo "  --verbose     Show all scanned files"
  echo "  --help        Show this help"
  echo ""
  echo "Exit codes: 0=clean  1=suspicious  2=compromised"
}

for arg in "$@"; do
  case "$arg" in
    --no-color) USE_COLOR=false ;;
    --json)     JSON_OUTPUT=true; USE_COLOR=false ;;
    --verbose)  VERBOSE=true ;;
    --help|-h)  usage; exit 0 ;;
    --*)        echo "Unknown option: $arg" >&2; usage; exit 1 ;;
    *)          SCAN_DIR="$arg" ;;
  esac
done

setup_colors

# --- Platform detection ------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Linux*)   PLATFORM="linux" ;;
  Darwin*)  PLATFORM="macos" ;;
  *)        PLATFORM="unknown" ;;
esac

# --- SHA256 verification helper ----------------------------------------------
sha256_of() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$file" 2>/dev/null | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
  fi
}

# --- Phase 1: Package lockfiles ----------------------------------------------
scan_lockfiles() {
  header "Phase 1/4 — Package lockfiles"

  # Find all supported lockfile types, skip node_modules/.git/.cache
  local lockfiles
  lockfiles=$(find "$SCAN_DIR" \
    \( -name "node_modules" -o -name ".git" -o -name ".cache" \) -prune \
    -o \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print \
    2>/dev/null)

  if [ -z "$lockfiles" ]; then
    info "No lockfiles found under $SCAN_DIR"
    return
  fi

  local count=0
  while IFS= read -r lockfile; do
    [ -z "$lockfile" ] && continue
    count=$((count + 1))
    $VERBOSE && info "Scanning: $lockfile"

    # --- Check for compromised axios versions (all lockfile formats) ---
    # Handles: "axios" (deps format), "node_modules/axios" (lockfileVersion 3), yarn "axios@x.y.z"
    if grep -qE '"?(node_modules/)?axios"?' "$lockfile" 2>/dev/null; then
      local bad_ver
      bad_ver=$(awk '
        /["\/]axios"?[[:space:]]*[:{]/ { in_axios=1; lines_since=0 }
        in_axios { lines_since++ }
        in_axios && /"version"[[:space:]]*:[[:space:]]*"(1\.14\.1|0\.30\.4)"/ {
          match($0, /"[0-9][^"]*"/)
          print substr($0, RSTART+1, RLENGTH-2)
          in_axios=0
        }
        in_axios && lines_since > 15 { in_axios=0 }
      ' "$lockfile" 2>/dev/null)

      if [ -n "$bad_ver" ]; then
        danger "COMPROMISED axios@$bad_ver in: $lockfile"
        FINDINGS_PACKAGES+=("$lockfile: axios@$bad_ver")
        [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
      fi
    fi

    # --- Check for all malicious packages ---

    # plain-crypto-js (any version = red flag; 4.2.1 = dropper; 4.2.0 = suspicious decoy)
    if grep -q 'plain-crypto-js' "$lockfile" 2>/dev/null; then
      local pcjs_ver
      pcjs_ver=$(awk '
        /plain-crypto-js/ { in_pkg=1; lines_since=0 }
        in_pkg { lines_since++ }
        in_pkg && /"version"/ {
          match($0, /"[0-9][^"]*"/)
          print substr($0, RSTART+1, RLENGTH-2)
          in_pkg=0
        }
        in_pkg && lines_since > 15 { in_pkg=0 }
      ' "$lockfile" 2>/dev/null)

      if [ "$pcjs_ver" = "4.2.1" ]; then
        danger "RAT DROPPER (SILKBELL): plain-crypto-js@4.2.1 in: $lockfile"
        FINDINGS_PACKAGES+=("$lockfile: plain-crypto-js@4.2.1 (SILKBELL dropper)")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      elif [ "$pcjs_ver" = "4.2.0" ]; then
        warn "SUSPICIOUS: plain-crypto-js@4.2.0 (decoy package) in: $lockfile"
        warn "  This package was published by attacker as cover 18h before the attack"
        FINDINGS_PACKAGES+=("$lockfile: plain-crypto-js@4.2.0 (attacker decoy)")
        [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
      else
        danger "plain-crypto-js found (any version = suspicious): $lockfile"
        FINDINGS_PACKAGES+=("$lockfile: plain-crypto-js@${pcjs_ver:-unknown}")
        [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
      fi
    fi

    # @shadanai/openclaw (vendored malicious plain-crypto-js)
    if grep -q '@shadanai/openclaw' "$lockfile" 2>/dev/null; then
      local oc_ver
      oc_ver=$(grep '@shadanai/openclaw' "$lockfile" | grep -oE '2026\.[0-9.]+' | head -1)
      danger "COMPROMISED package: @shadanai/openclaw${oc_ver:+@$oc_ver} in: $lockfile"
      danger "  This package vendors malicious plain-crypto-js"
      FINDINGS_PACKAGES+=("$lockfile: @shadanai/openclaw@${oc_ver:-unknown}")
      [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
    fi

    # @qqbrowser/openclaw-qbot (ships compromised axios in its node_modules)
    if grep -q 'openclaw-qbot' "$lockfile" 2>/dev/null; then
      local qb_ver
      qb_ver=$(awk '/openclaw-qbot/ { in_pkg=1 } in_pkg && /"version"/ { match($0,/"[0-9][^"]*"/); print substr($0,RSTART+1,RLENGTH-2); exit }' "$lockfile" 2>/dev/null)
      if [ "${qb_ver}" = "0.0.130" ]; then
        danger "COMPROMISED package: @qqbrowser/openclaw-qbot@0.0.130 in: $lockfile"
        FINDINGS_PACKAGES+=("$lockfile: @qqbrowser/openclaw-qbot@0.0.130")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      fi
    fi

  done <<< "$lockfiles"

  if [ ${#FINDINGS_PACKAGES[@]} -eq 0 ]; then
    ok "Scanned $count lockfile(s) — no compromised packages found"
  fi
}

# --- Phase 2: node_modules ---------------------------------------------------
scan_node_modules() {
  header "Phase 2/4 — node_modules"

  local found_modules
  found_modules=$(find "$SCAN_DIR" -type d -name "node_modules" 2>/dev/null | \
    grep -v "node_modules/node_modules")

  if [ -z "$found_modules" ]; then
    info "No node_modules directories found"
    return
  fi

  local count=0
  while IFS= read -r nm_dir; do
    [ -z "$nm_dir" ] && continue
    count=$((count + 1))
    $VERBOSE && info "Checking: $nm_dir"

    # --- plain-crypto-js ---
    if [ -d "$nm_dir/plain-crypto-js" ]; then
      local pcjs_ver="" has_setup=""
      [ -f "$nm_dir/plain-crypto-js/package.json" ] && \
        pcjs_ver=$(grep -m1 '"version"' "$nm_dir/plain-crypto-js/package.json" 2>/dev/null | \
          grep -o '"[0-9][^"]*"' | tr -d '"')
      [ -f "$nm_dir/plain-crypto-js/setup.js" ] && has_setup="yes"

      if [ -n "$has_setup" ]; then
        # setup.js present — dropper is loaded, hasn't run yet
        danger "SILKBELL DROPPER LOADED (not yet executed): $nm_dir/plain-crypto-js@${pcjs_ver}"
        danger "  setup.js present — will execute on next npm install"
        FINDINGS_MODULES+=("$nm_dir/plain-crypto-js@${pcjs_ver} (setup.js present)")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      elif [ "$pcjs_ver" = "4.2.1" ]; then
        # Directory exists, no setup.js → dropper self-deleted after execution
        danger "DROPPER ALREADY EXECUTED: $nm_dir/plain-crypto-js@4.2.1"
        danger "  setup.js is gone — SILKBELL ran and self-deleted. System was exposed."
        FINDINGS_MODULES+=("$nm_dir/plain-crypto-js@4.2.1 (dropper ran, self-deleted)")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      else
        # Any other version of plain-crypto-js is also suspicious
        warn "SUSPICIOUS: plain-crypto-js@${pcjs_ver:-unknown} in $nm_dir"
        warn "  This package should never be a legitimate dependency"
        FINDINGS_MODULES+=("$nm_dir/plain-crypto-js@${pcjs_ver:-unknown} (suspicious)")
        [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
      fi
    fi

    # --- axios version check ---
    local axios_pkg="$nm_dir/axios/package.json"
    if [ -f "$axios_pkg" ]; then
      local installed_ver
      installed_ver=$(grep -m1 '"version"' "$axios_pkg" 2>/dev/null | \
        grep -o '"[0-9][^"]*"' | tr -d '"')
      case "$installed_ver" in
        1.14.1|0.30.4)
          danger "COMPROMISED axios@$installed_ver installed: $nm_dir"
          FINDINGS_MODULES+=("$nm_dir/axios@$installed_ver")
          [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
          ;;
      esac
    fi

    # --- @shadanai/openclaw ---
    if [ -d "$nm_dir/@shadanai" ]; then
      local oc_dirs
      oc_dirs=$(ls "$nm_dir/@shadanai/" 2>/dev/null | grep "openclaw")
      if [ -n "$oc_dirs" ]; then
        danger "COMPROMISED @shadanai/openclaw installed: $nm_dir/@shadanai/"
        FINDINGS_MODULES+=("$nm_dir/@shadanai/openclaw")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      fi
    fi

  done <<< "$found_modules"

  if [ ${#FINDINGS_MODULES[@]} -eq 0 ]; then
    ok "Checked $count node_modules — no malicious packages installed"
  fi
}

# --- Phase 3: Filesystem RAT artifacts ---------------------------------------
scan_artifacts() {
  header "Phase 3/4 — Filesystem artifacts (RAT)"

  local artifacts_found=0

  check_artifact() {
    local path="$1"
    local label="$2"
    local expected_sha256="${3:-}"
    if [ -e "$path" ]; then
      local actual_sha256=""
      [ -f "$path" ] && actual_sha256=$(sha256_of "$path")
      local sha_note=""
      if [ -n "$expected_sha256" ] && [ -n "$actual_sha256" ]; then
        if [ "$actual_sha256" = "$expected_sha256" ]; then
          sha_note=" ${RED}[SHA256 MATCH — confirmed RAT binary]${RESET}"
        else
          sha_note=" ${YELLOW}[SHA256 mismatch — verify manually]${RESET}"
        fi
      fi
      danger "RAT ARTIFACT: $label"
      _out "       Path: $path"
      [ -n "$actual_sha256" ] && _out "       SHA256: $actual_sha256$sha_note"
      _out "       Size/Modified: $(du -sh "$path" 2>/dev/null | cut -f1) / $(stat -c '%y' "$path" 2>/dev/null || stat -f '%Sm' "$path" 2>/dev/null)"
      FINDINGS_ARTIFACTS+=("$path")
      [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      artifacts_found=$((artifacts_found + 1))
    fi
  }

  case "$PLATFORM" in
    macos)
      check_artifact \
        "/Library/Caches/com.apple.act.mond" \
        "macOS WAVESHAPER.V2 binary (system)" \
        "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"
      check_artifact \
        "$HOME/Library/Caches/com.apple.act.mond" \
        "macOS WAVESHAPER.V2 binary (user)" \
        "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"

      # LaunchAgent persistence (deployed via 'runscript' after initial compromise)
      local la_dir="$HOME/Library/LaunchAgents"
      if [ -d "$la_dir" ]; then
        local suspicious_plists
        suspicious_plists=$(find "$la_dir" -name "*.plist" -newer /tmp/axios-scan-ref 2>/dev/null \
          -exec grep -l "act.mond\|sfrclak\|6202033" {} \; 2>/dev/null || true)
        if [ -n "$suspicious_plists" ]; then
          while IFS= read -r plist; do
            danger "RAT PERSISTENCE: LaunchAgent plist containing IOCs"
            _out "       Path: $plist"
            FINDINGS_ARTIFACTS+=("$plist (LaunchAgent)")
            [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
            artifacts_found=$((artifacts_found + 1))
          done <<< "$suspicious_plists"
        fi
      fi
      ;;

    linux)
      check_artifact \
        "/tmp/ld.py" \
        "Linux WAVESHAPER.V2 Python script" \
        "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"

      # Check if ld.py is running as a process even if file was deleted
      if pgrep -f "/tmp/ld.py" &>/dev/null 2>&1; then
        local pid
        pid=$(pgrep -f "/tmp/ld.py" | head -1)
        danger "RAT RUNNING IN MEMORY: /tmp/ld.py (PID $pid) — file may be deleted but process is live"
        FINDINGS_ARTIFACTS+=("/tmp/ld.py (process running, PID $pid)")
        [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
        artifacts_found=$((artifacts_found + 1))
      fi

      # Alternative hash
      if [ -f "/tmp/ld.py" ]; then
        local actual_hash
        actual_hash=$(sha256_of "/tmp/ld.py")
        if [ "$actual_hash" = "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7" ]; then
          danger "RAT ARTIFACT (alt hash): /tmp/ld.py — confirmed WAVESHAPER.V2"
          FINDINGS_ARTIFACTS+=("/tmp/ld.py (alt hash confirmed)")
          [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
          artifacts_found=$((artifacts_found + 1))
        fi
      fi
      ;;
  esac

  # RAT temp files (self-deleting but worth checking on all platforms)
  for f in /tmp/6202033.* /var/tmp/6202033.* "${TMPDIR:-/tmp}/6202033."*; do
    [ -e "$f" ] && check_artifact "$f" "RAT temp file (campaign ID)"
  done

  if [ "$artifacts_found" -eq 0 ]; then
    ok "No RAT artifacts found (platform: $PLATFORM)"
  fi
}

# --- Phase 4: Network IOCs ---------------------------------------------------
scan_network() {
  header "Phase 4/4 — Network connections & indicators"

  local C2_DOMAINS=("sfrclak.com" "calltan.com" "callnrwise.com" "hopex.pro" "coretrade.app")
  local C2_IPS=("142.11.206.73" "23.254.167.216" "45.61.128.54" "144.172.89.231")
  local C2_UA="msie 8.0"  # substring of the hardcoded anachronistic user-agent
  local network_hits=0

  # --- Active connections ---
  local active_conns=""
  if command -v ss &>/dev/null; then
    for ip in "${C2_IPS[@]}"; do
      local conn
      conn=$(ss -tnp 2>/dev/null | grep "$ip" || true)
      [ -n "$conn" ] && active_conns+="$conn"$'\n'
    done
  elif command -v netstat &>/dev/null; then
    for ip in "${C2_IPS[@]}"; do
      local conn
      conn=$(netstat -tn 2>/dev/null | grep "$ip" || true)
      [ -n "$conn" ] && active_conns+="$conn"$'\n'
    done
  fi

  if [ -n "$active_conns" ]; then
    danger "ACTIVE C2 CONNECTION:"
    while IFS= read -r line; do
      [ -n "$line" ] && _out "       $line"
    done <<< "$active_conns"
    FINDINGS_NETWORK+=("active connection to C2")
    [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
    network_hits=$((network_hits + 1))
  fi

  # --- DNS: do C2 domains still resolve? ---
  if command -v host &>/dev/null || command -v nslookup &>/dev/null; then
    for domain in "${C2_DOMAINS[@]}"; do
      local dns_result=""
      if command -v host &>/dev/null; then
        dns_result=$(host "$domain" 2>/dev/null | grep "address" | grep -v "not found" || true)
      else
        dns_result=$(nslookup "$domain" 2>/dev/null | grep "Address" | tail -n +2 || true)
      fi
      if [ -n "$dns_result" ]; then
        warn "C2 domain still resolves: $domain"
        info "  $dns_result"
        # Resolving domain ≠ compromised, but worth noting
      fi
    done
  fi

  # --- /etc/hosts poisoning ---
  for domain in "${C2_DOMAINS[@]}"; do
    if grep -q "$domain" /etc/hosts 2>/dev/null; then
      danger "C2 domain in /etc/hosts: $domain"
      FINDINGS_NETWORK+=("/etc/hosts contains C2 indicator: $domain")
      [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      network_hits=$((network_hits + 1))
    fi
  done
  for ip in "${C2_IPS[@]}"; do
    if grep -q "$ip" /etc/hosts 2>/dev/null; then
      danger "C2 IP in /etc/hosts: $ip"
      FINDINGS_NETWORK+=("/etc/hosts contains C2 IP: $ip")
      [ "$EXIT_CODE" -lt 2 ] && EXIT_CODE=2
      network_hits=$((network_hits + 1))
    fi
  done

  # --- npm proxy logs / access logs for C2 User-Agent or domain ---
  local npm_logs_dir="${HOME}/.npm/_logs"
  if [ -d "$npm_logs_dir" ]; then
    local log_hits
    log_hits=$(grep -rl "sfrclak\|plain-crypto-js.*4\.2\.1\|$C2_UA" "$npm_logs_dir" 2>/dev/null || true)
    if [ -n "$log_hits" ]; then
      warn "C2 indicators found in npm logs:"
      while IFS= read -r logfile; do
        warn "  $logfile"
        FINDINGS_NETWORK+=("npm log: $logfile")
      done <<< "$log_hits"
      [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
    fi
  fi

  # --- npm cache: check for malicious tarballs ---
  local npm_cache_dir
  npm_cache_dir=$(npm config get cache 2>/dev/null || echo "")
  if [ -n "$npm_cache_dir" ] && [ -d "$npm_cache_dir" ]; then
    local bad_cache
    bad_cache=$(find "$npm_cache_dir" -type f -name "*.json" 2>/dev/null | \
      xargs grep -l '"plain-crypto-js"' 2>/dev/null | head -5 || true)
    if [ -n "$bad_cache" ]; then
      warn "Malicious package evidence in npm cache:"
      while IFS= read -r cf; do
        warn "  $cf"
        FINDINGS_CACHE+=("npm cache: $cf")
      done <<< "$bad_cache"
      warn "  Run: npm cache clean --force"
      [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
    fi

    # Also check yarn cache
    local yarn_cache_dir
    yarn_cache_dir=$(yarn cache dir 2>/dev/null || echo "")
    if [ -n "$yarn_cache_dir" ] && [ -d "$yarn_cache_dir" ]; then
      local yarn_bad
      yarn_bad=$(find "$yarn_cache_dir" -name "plain-crypto-js" -type d 2>/dev/null | head -3 || true)
      if [ -n "$yarn_bad" ]; then
        warn "plain-crypto-js in yarn cache:"
        while IFS= read -r yd; do
          warn "  $yd"
          FINDINGS_CACHE+=("yarn cache: $yd")
        done <<< "$yarn_bad"
        warn "  Run: yarn cache clean"
        [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1
      fi
    fi
  fi

  if [ "$network_hits" -eq 0 ] && [ ${#FINDINGS_CACHE[@]} -eq 0 ]; then
    ok "No active C2 connections or cache hits detected"
  fi
}

# --- JSON output -------------------------------------------------------------
output_json() {
  local status
  case "$EXIT_CODE" in
    0) status="CLEAN" ;;
    1) status="SUSPICIOUS" ;;
    2) status="COMPROMISED" ;;
  esac

  local all_findings=()
  for f in \
    "${FINDINGS_PACKAGES[@]+"${FINDINGS_PACKAGES[@]}"}" \
    "${FINDINGS_MODULES[@]+"${FINDINGS_MODULES[@]}"}" \
    "${FINDINGS_ARTIFACTS[@]+"${FINDINGS_ARTIFACTS[@]}"}" \
    "${FINDINGS_NETWORK[@]+"${FINDINGS_NETWORK[@]}"}" \
    "${FINDINGS_CACHE[@]+"${FINDINGS_CACHE[@]}"}"; do
    all_findings+=("$f")
  done

  echo "{"
  printf '  "scanner": "axios-scan.sh",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "timestamp": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "platform": "%s",\n' "$PLATFORM"
  printf '  "scan_dir": "%s",\n' "$(realpath "$SCAN_DIR" 2>/dev/null || echo "$SCAN_DIR")"
  printf '  "status": "%s",\n' "$status"
  printf '  "exit_code": %d,\n' "$EXIT_CODE"
  printf '  "advisory": "GHSA-fw8c-xr5c-95f9",\n'
  printf '  "findings": {\n'

  _json_arr() {
    local name="$1"; shift
    printf '    "%s": [' "$name"
    local sep=""
    for v in "$@"; do
      local escaped="${v//\"/\\\"}"
      printf '%s"%s"' "$sep" "$escaped"; sep=", "
    done
    printf ']'
  }

  _json_arr "lockfiles"    "${FINDINGS_PACKAGES[@]+"${FINDINGS_PACKAGES[@]}"}"
  echo ","
  _json_arr "node_modules" "${FINDINGS_MODULES[@]+"${FINDINGS_MODULES[@]}"}"
  echo ","
  _json_arr "filesystem"   "${FINDINGS_ARTIFACTS[@]+"${FINDINGS_ARTIFACTS[@]}"}"
  echo ","
  _json_arr "network"      "${FINDINGS_NETWORK[@]+"${FINDINGS_NETWORK[@]}"}"
  echo ","
  _json_arr "cache"        "${FINDINGS_CACHE[@]+"${FINDINGS_CACHE[@]}"}"
  echo ""
  echo "  }"
  echo "}"
}

# --- Summary -----------------------------------------------------------------
print_summary() {
  local total_findings=$(( \
    ${#FINDINGS_PACKAGES[@]} + \
    ${#FINDINGS_MODULES[@]} + \
    ${#FINDINGS_ARTIFACTS[@]} + \
    ${#FINDINGS_NETWORK[@]} + \
    ${#FINDINGS_CACHE[@]} \
  ))

  echo ""
  echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"

  case "$EXIT_CODE" in
    0)
      echo -e "${BOLD}${GREEN}  RESULT: CLEAN${RESET}"
      echo -e "  No signs of the axios supply chain compromise detected."
      ;;
    1)
      echo -e "${BOLD}${YELLOW}  RESULT: SUSPICIOUS — $total_findings finding(s)${RESET}"
      echo ""
      echo -e "${YELLOW}  Compromised axios version found in lockfile/cache.${RESET}"
      echo -e "  Check if npm install ran during the exposure window:"
      echo -e "  ${DIM}2026-03-31  00:21 – 03:25 UTC${RESET}"
      echo ""
      echo -e "  Remediation:"
      echo -e "  1. Downgrade:  npm install axios@1.14.0  (or 0.30.3 for 0.x)"
      echo -e "  2. Remove:     rm -rf node_modules/plain-crypto-js"
      echo -e "  3. Clean:      npm cache clean --force && yarn cache clean"
      echo -e "  4. Reinstall:  rm -rf node_modules && npm install"
      echo -e "  5. Audit CI:   check pipeline logs from exposure window"
      ;;
    2)
      echo -e "${BOLD}${RED}  RESULT: COMPROMISED — $total_findings finding(s)${RESET}"
      echo ""
      echo -e "${RED}  WAVESHAPER.V2 RAT artifacts or active C2 communication detected."
      echo -e "  Assume full system compromise. All credentials exposed.${RESET}"
      echo ""
      echo -e "  ${BOLD}Immediate actions:${RESET}"
      echo -e "  1. ${RED}ISOLATE${RESET} this machine from the network NOW"
      echo -e "  2. Rotate ALL credentials:"
      echo -e "     - npm tokens    (~/.npmrc)"
      echo -e "     - SSH keys      (~/.ssh/)"
      echo -e "     - Cloud creds   (~/.aws/, ~/.azure/, ~/.config/gcloud/)"
      echo -e "     - CI/CD secrets (GitHub Actions, GitLab CI, etc.)"
      echo -e "     - .env files    (database passwords, API keys)"
      echo -e "  3. Preserve disk image before cleanup (forensics)"
      echo -e "  4. Check CI/CD pipelines — attackers target pipeline tokens"
      echo -e "  5. Report to your security team"
      echo -e "  6. File: GHSA-fw8c-xr5c-95f9"
      ;;
  esac

  echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
  echo ""
}

# --- Entrypoint --------------------------------------------------------------

# Create a reference timestamp for LaunchAgent scan (macOS)
touch /tmp/axios-scan-ref 2>/dev/null || true

if ! $JSON_OUTPUT; then
  echo -e "${BOLD}axios-scan.sh v${VERSION}${RESET}  |  WAVESHAPER.V2 / axios Supply Chain Detector"
  echo -e "${DIM}Scanning: $(realpath "$SCAN_DIR" 2>/dev/null || echo "$SCAN_DIR")${RESET}"
  echo -e "${DIM}Platform: $PLATFORM  |  Advisory: GHSA-fw8c-xr5c-95f9  |  $(date -u)${RESET}"
fi

scan_lockfiles
scan_node_modules
scan_artifacts
scan_network

if $JSON_OUTPUT; then
  output_json
else
  print_summary
fi

rm -f /tmp/axios-scan-ref 2>/dev/null || true
exit "$EXIT_CODE"
