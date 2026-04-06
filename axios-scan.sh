#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack Scanner
# Scans for compromised axios@1.14.1, axios@0.30.4, and plain-crypto-js
# Attack date: March 31, 2026 | Attribution: Sapphire Sleet / UNC1069
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FOUND_ISSUES=0
SCANNED_PROJECTS=0
LOG_FILE="$HOME/axios-scan-results-$(date +%Y%m%d-%H%M%S).log"

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
  echo -e "${CYAN}${BOLD}  Axios Supply Chain Attack Scanner (March 2026)${NC}"
  echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
  echo -e "  Malicious versions: ${RED}axios@1.14.1${NC} | ${RED}axios@0.30.4${NC}"
  echo -e "  Malicious dep:      ${RED}plain-crypto-js@4.2.1${NC}"
  echo -e "  Safe versions:      ${GREEN}axios@1.14.0${NC} | ${GREEN}axios@0.30.3${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
  echo ""
}

log() {
  echo "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

alert() {
  echo -e "${RED}${BOLD}  [!] ALERT: $1${NC}"
  log "[!] ALERT: $1"
  FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

ok() {
  echo -e "${GREEN}  [✓] $1${NC}"
  log "[✓] $1"
}

info() {
  echo -e "${YELLOW}  [i] $1${NC}"
  log "[i] $1"
}

section() {
  echo ""
  echo -e "${BOLD}▶ $1${NC}"
  log ""
  log "▶ $1"
}

# --------------------------------------------------------------------------
# 1. LOCKFILE SCAN
# --------------------------------------------------------------------------
scan_lockfiles() {
  section "Scanning lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml)..."

  local search_dirs=("$HOME" "/var/www" "/opt" "/srv" "/usr/local")

  for dir in "${search_dirs[@]}"; do
    [ ! -d "$dir" ] && continue

    while IFS= read -r lockfile; do
      SCANNED_PROJECTS=$((SCANNED_PROJECTS + 1))

      # Check for malicious axios versions
      if grep -qE '"axios".*"1\.14\.1"|"axios".*"0\.30\.4"|axios@1\.14\.1|axios@0\.30\.4' "$lockfile" 2>/dev/null; then
        alert "Compromised Axios found in: $lockfile"
      fi

      # Check for plain-crypto-js (should NEVER exist)
      if grep -q "plain-crypto-js" "$lockfile" 2>/dev/null; then
        alert "Malicious dependency plain-crypto-js in: $lockfile"
      fi

    done < <(find "$dir" \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
      -not -path "*/node_modules/*" -not -path "*/.cache/*" -not -path "*/Library/Caches/*" 2>/dev/null)
  done

  [ "$SCANNED_PROJECTS" -eq 0 ] && info "No lockfiles found." || ok "Scanned $SCANNED_PROJECTS lockfile(s)."
}

# --------------------------------------------------------------------------
# 2. NODE_MODULES SCAN
# --------------------------------------------------------------------------
scan_node_modules() {
  section "Scanning installed node_modules for compromised packages..."

  local search_dirs=("$HOME" "/var/www" "/opt" "/srv" "/usr/local")

  for dir in "${search_dirs[@]}"; do
    [ ! -d "$dir" ] && continue

    # Check for plain-crypto-js directories (absolute red flag)
    while IFS= read -r pcp_dir; do
      alert "plain-crypto-js installed at: $pcp_dir"

      # Check for the dropper
      if [ -f "$pcp_dir/setup.js" ]; then
        alert "Malicious dropper (setup.js) found at: $pcp_dir/setup.js"
      fi
    done < <(find "$dir" -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null)

    # Check axios package.json for bad versions
    while IFS= read -r axios_pkg; do
      local ver
      ver=$(grep -o '"version": *"[^"]*"' "$axios_pkg" 2>/dev/null | head -1 | grep -o '[0-9][^"]*')
      if [ "$ver" = "1.14.1" ] || [ "$ver" = "0.30.4" ]; then
        alert "Compromised axios@$ver installed at: $axios_pkg"
      fi
    done < <(find "$dir" -path "*/node_modules/axios/package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null)
  done

  ok "node_modules scan complete."
}

# --------------------------------------------------------------------------
# 3. GLOBAL NPM / YARN / PNPM CHECK
# --------------------------------------------------------------------------
scan_global_packages() {
  section "Checking globally installed packages..."

  # npm global
  if command -v npm &>/dev/null; then
    local npm_axios
    npm_axios=$(npm list -g axios 2>/dev/null | grep axios || true)
    if echo "$npm_axios" | grep -qE "1\.14\.1|0\.30\.4"; then
      alert "Compromised Axios installed globally via npm: $npm_axios"
    elif [ -n "$npm_axios" ]; then
      ok "Global npm axios is safe: $npm_axios"
    else
      ok "Axios not installed globally via npm."
    fi
  fi

  # yarn global
  if command -v yarn &>/dev/null; then
    local yarn_axios
    yarn_axios=$(yarn global list 2>/dev/null | grep axios || true)
    if echo "$yarn_axios" | grep -qE "1\.14\.1|0\.30\.4"; then
      alert "Compromised Axios installed globally via yarn: $yarn_axios"
    elif [ -n "$yarn_axios" ]; then
      ok "Global yarn axios is safe."
    fi
  fi

  # pnpm global
  if command -v pnpm &>/dev/null; then
    local pnpm_axios
    pnpm_axios=$(pnpm list -g axios 2>/dev/null | grep axios || true)
    if echo "$pnpm_axios" | grep -qE "1\.14\.1|0\.30\.4"; then
      alert "Compromised Axios installed globally via pnpm: $pnpm_axios"
    elif [ -n "$pnpm_axios" ]; then
      ok "Global pnpm axios is safe."
    fi
  fi
}

# --------------------------------------------------------------------------
# 4. NPM CACHE SCAN
# --------------------------------------------------------------------------
scan_npm_cache() {
  section "Scanning npm/yarn/pnpm caches..."

  local npm_cache="${NPM_CONFIG_CACHE:-$HOME/.npm}"
  local yarn_cache="$HOME/.cache/yarn"
  local pnpm_cache="$HOME/.local/share/pnpm/store"

  for cache_dir in "$npm_cache" "$yarn_cache" "$pnpm_cache"; do
    [ ! -d "$cache_dir" ] && continue

    if find "$cache_dir" -name "*.tgz" -o -name "*.tar.gz" 2>/dev/null | xargs grep -l "plain-crypto-js" 2>/dev/null | head -1 | grep -q .; then
      alert "Malicious package found in cache: $cache_dir"
      info "Run: npm cache clean --force (or equivalent) to purge."
    fi

    if find "$cache_dir" -type d -name "plain-crypto-js" 2>/dev/null | head -1 | grep -q .; then
      alert "plain-crypto-js cached in: $cache_dir"
    fi
  done

  ok "Cache scan complete."
}

# --------------------------------------------------------------------------
# 5. RAT ARTIFACT SCAN (post-compromise indicators)
# --------------------------------------------------------------------------
scan_rat_artifacts() {
  section "Scanning for RAT artifacts and IOCs..."

  # Known C2 domain in hosts/DNS cache or network configs
  local c2_domain="sfrclak.com"
  if grep -rq "$c2_domain" /etc/hosts 2>/dev/null; then
    alert "C2 domain ($c2_domain) found in /etc/hosts"
  fi

  # Check for persistence mechanisms (platform-specific)
  local os_type
  os_type=$(uname -s)

  case "$os_type" in
    Darwin)
      # macOS: check LaunchAgents / LaunchDaemons
      for plist_dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
        if [ -d "$plist_dir" ]; then
          while IFS= read -r plist; do
            if grep -ql "$c2_domain\|plain-crypto-js\|setup\.js.*node" "$plist" 2>/dev/null; then
              alert "Suspicious LaunchAgent/Daemon: $plist"
            fi
          done < <(find "$plist_dir" -name "*.plist" 2>/dev/null)
        fi
      done
      ;;
    Linux)
      # Linux: check cron, systemd user services
      if crontab -l 2>/dev/null | grep -q "$c2_domain\|plain-crypto-js"; then
        alert "Suspicious crontab entry referencing attack IOCs"
      fi
      if find "$HOME/.config/systemd/user" -name "*.service" 2>/dev/null | xargs grep -l "$c2_domain\|plain-crypto-js" 2>/dev/null | head -1 | grep -q .; then
        alert "Suspicious systemd user service found"
      fi
      ;;
  esac

  # Check running processes for C2 connections
  if ps aux 2>/dev/null | grep -v grep | grep -q "$c2_domain"; then
    alert "Active process communicating with C2 domain!"
  fi

  # Check for the XOR key used in the dropper obfuscation
  if find "$HOME" -maxdepth 5 -name "setup.js" 2>/dev/null | xargs grep -l "OrDeR_7077" 2>/dev/null | head -1 | grep -q .; then
    alert "Axios dropper obfuscation key (OrDeR_7077) found in a setup.js file"
  fi

  ok "RAT artifact scan complete."
}

# --------------------------------------------------------------------------
# 6. NETWORK IOC CHECK
# --------------------------------------------------------------------------
scan_network_iocs() {
  section "Checking network connections for known C2..."

  local c2_domain="sfrclak.com"

  # Active connections
  if command -v ss &>/dev/null; then
    if ss -tunp 2>/dev/null | grep -q "$c2_domain"; then
      alert "Active network connection to C2: $c2_domain"
    fi
  elif command -v netstat &>/dev/null; then
    if netstat -an 2>/dev/null | grep -q "$c2_domain"; then
      alert "Active network connection to C2: $c2_domain"
    fi
  fi

  # DNS cache (macOS)
  if command -v dscacheutil &>/dev/null; then
    if dscacheutil -cachedump 2>/dev/null | grep -q "$c2_domain"; then
      alert "C2 domain in DNS cache"
    fi
  fi

  ok "Network IOC check complete."
}

# --------------------------------------------------------------------------
# RESULTS SUMMARY
# --------------------------------------------------------------------------
print_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
  if [ "$FOUND_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✅ ALL CLEAR — No compromised Axios found.${NC}"
    echo -e "${GREEN}     Scanned $SCANNED_PROJECTS project(s).${NC}"
  else
    echo -e "${RED}${BOLD}  🚨 $FOUND_ISSUES ISSUE(S) FOUND — ACTION REQUIRED${NC}"
    echo ""
    echo -e "${YELLOW}  Remediation steps:${NC}"
    echo -e "  1. Downgrade to axios@1.14.0 or axios@0.30.3"
    echo -e "  2. Delete node_modules/plain-crypto-js everywhere"
    echo -e "  3. npm cache clean --force"
    echo -e "  4. Delete node_modules & reinstall from clean lockfile"
    echo -e "  5. ${RED}${BOLD}ROTATE ALL SECRETS${NC} (API keys, tokens, SSH keys,"
    echo -e "     DB passwords, .env vars, CI/CD secrets)"
    echo -e "  6. Block egress to sfrclak[.]com at firewall"
    echo -e "  7. Audit CI/CD logs from March 31 00:21–03:30 UTC"
  fi
  echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
  echo -e "  Full log saved to: ${BOLD}$LOG_FILE${NC}"
  echo ""
}

# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
banner
echo "Starting full machine scan... (this may take a minute)"
echo "Scan started: $(date)" > "$LOG_FILE"
log "=================================="

scan_lockfiles
scan_node_modules
scan_global_packages
scan_npm_cache
scan_rat_artifacts
scan_network_iocs
print_summary
