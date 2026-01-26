#!/usr/bin/env bash
# ubuntu-to-mint-convert-v3.sh
#
# Copyright (C) 2026 LINUXexpert.org
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

set -euo pipefail

# =========================
# Version
# =========================
SCRIPT_VERSION="5.1"
# v5.1 changes:
# - Added deterministic temp-dir cleanup (EXIT trap)
# - Added dependency + disk-space preflight gates
# - Improved plan-mode sandbox permissions and _apt sandbox user
# - Added APT health gate to reduce "first run partial, second run finishes"
# - Keyring overwrite now backed up before replacement
# - Added desktop-session validity diagnostics after install
# - Hardened display-manager.service enablement (systemd alias mechanics)

# =========================
# Globals / Defaults
# =========================
LOG_DIR="/var/log/ubuntu-to-mint"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/ubuntu-to-mint-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Temp tracking (cleanup on exit)
TEMP_DIRS=()

# CLI defaults
CMD=""
EDITION="cinnamon"
TARGET_MINT=""
MINT_MIRROR="http://packages.linuxmint.com"
KEEP_PPAS="no"
PRESERVE_SNAP="yes"
WITH_RECOMMENDS="no"
ASSUME_YES="no"
I_ACCEPT_RISK="no"
ROLLBACK_DIR=""

# OS detection
OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""
UBUNTU_BASE=""
DEFAULT_MINT=""
ALLOWED_TARGETS=()   # array

# Key handling
MINT_KEYID="A6616109451BBBF2"
SYSTEM_KEYRING="/usr/share/keyrings/linuxmint-repo.gpg"

# Error handling
ON_ERROR_BACKUP_HINT=""

# =========================
# Error + cleanup traps
# =========================
register_tmpdir() {
  local d="${1:-}"
  [[ -n "$d" ]] || return 0
  TEMP_DIRS+=("$d")
}

cleanup() {
  # Never fail cleanup
  set +e
  if [[ ${#TEMP_DIRS[@]:-0} -gt 0 ]]; then
    for d in "${TEMP_DIRS[@]:-}"; do
      [[ -n "${d:-}" ]] || continue
      rm -rf "$d" 2>/dev/null || true
    done
  fi
  set -e
}

on_err() {
  local rc=$?
  local line="${BASH_LINENO[0]:-unknown}"
  echo "ERROR: FAILED at line ${line} (exit ${rc})."
  echo "ERROR: Command: ${BASH_COMMAND}"
  [[ -n "${ON_ERROR_BACKUP_HINT:-}" ]] && echo "${ON_ERROR_BACKUP_HINT}"
  exit "$rc"
}

trap on_err ERR
trap cleanup EXIT

# =========================
# Pretty output
# =========================
is_tty() { [[ -t 1 ]]; }

if is_tty && command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

info() { echo "${BLUE}INFO:${RESET}  $*"; }
ok()   { echo "${GREEN}OK:${RESET}    $*"; }
warn() { echo "${YELLOW}WARN:${RESET}  $*"; }
die()  { echo "${RED}ERROR:${RESET} $*"; [[ -n "${ON_ERROR_BACKUP_HINT:-}" ]] && echo "${YELLOW}${ON_ERROR_BACKUP_HINT}${RESET}"; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "This must be run as root. Use: sudo bash $0 ..."
  fi
}

# =========================
# Usage
# =========================
usage() {
  cat <<EOF
ubuntu-to-mint-convert-v3.sh (v${SCRIPT_VERSION})

Usage (command-first):
  sudo bash $0 doctor [options]
  sudo bash $0 plan [options]
  sudo bash $0 convert --i-accept-the-risk [options]
  sudo bash $0 rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS

Usage (options-first ALSO supported):
  sudo bash $0 [options] doctor
  sudo bash $0 [options] plan
  sudo bash $0 [options] convert --i-accept-the-risk
  sudo bash $0 rollback /path/to/backup

Options:
  --edition cinnamon|mate|xfce     (default: cinnamon)
  --target <mint_codename>         Override Mint codename for your Ubuntu base
  --mint-mirror <url>              (default: http://packages.linuxmint.com)
  --keep-ppas                      Do not disable third-party sources (not recommended)
  --preserve-snap                  Keep snapd (default: enabled)
  --with-recommends                Allow recommended packages (default: off)
  --yes                            Non-interactive / auto-confirm (also allows non-TTY convert)
  --i-accept-the-risk              Required for convert
EOF
}

# =========================
# Preflight: deps + disk
# =========================
check_disk_space_gb() {
  local min_gb="${1:-2}"
  local mode="${2:-hard}"  # hard|warn
  local avail_kb
  avail_kb="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}' || echo 0)"
  [[ "$avail_kb" =~ ^[0-9]+$ ]] || avail_kb=0
  local avail_gb=$(( avail_kb / 1024 / 1024 ))

  if (( avail_gb < min_gb )); then
    if [[ "$mode" == "warn" ]]; then
      warn "Low disk space on /: ~${avail_gb}GB available (recommended >= ${min_gb}GB)."
      return 0
    fi
    die "Insufficient disk space on /: ~${avail_gb}GB available (need >= ${min_gb}GB). Free space and retry."
  fi

  ok "Disk space OK: ~${avail_gb}GB available (>= ${min_gb}GB)."
}

check_deps() {
  # allow_install: yes|no
  local allow_install="${1:-no}"

  local -a required_cmds=(bash awk sed grep find tee mktemp df apt-get dpkg apt-mark)
  local -a nice_cmds=(systemctl)
  local -a missing_cmds=()

  for c in "${required_cmds[@]}"; do
    have_cmd "$c" || missing_cmds+=("$c")
  done

  # lock checks rely on fuser (psmisc)
  have_cmd fuser || missing_cmds+=("fuser")

  if [[ ${#missing_cmds[@]} -gt 0 ]]; then
    warn "Missing required commands: ${missing_cmds[*]}"
    if [[ "$allow_install" != "yes" ]]; then
      die "Missing prerequisites. Install required packages (e.g., curl/gnupg/psmisc) or re-run with --yes to auto-install where safe."
    fi
  fi

  # Attempt safe installs when allowed
  if [[ "$allow_install" == "yes" ]]; then
    local -a pkgs=()
    have_cmd curl || pkgs+=(curl)
    have_cmd gpg || pkgs+=(gnupg)
    [[ -r /etc/ssl/certs/ca-certificates.crt ]] || pkgs+=(ca-certificates)
    have_cmd dpkg-deb || pkgs+=(dpkg-dev)
    have_cmd fuser || pkgs+=(psmisc)
    # Helps signed-by for Ubuntu repos
    [[ -r /usr/share/keyrings/ubuntu-archive-keyring.gpg ]] || pkgs+=(ubuntu-keyring)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
      info "Installing missing prerequisites (best-effort): ${pkgs[*]}"
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >/dev/null 2>&1 || true
    fi
  fi

  for c in "${nice_cmds[@]}"; do
    have_cmd "$c" || warn "Optional command not found: $c (some checks/automation may be limited)."
  done

  ok "Dependency preflight complete."
}

# =========================
# APT / dpkg sanity
# =========================
ensure_no_apt_locks() {
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
  for l in "${locks[@]}"; do
    if [[ -e "$l" ]] && fuser "$l" >/dev/null 2>&1; then
      die "APT/dpkg lock is held (lock file: $l). Close package managers and try again."
    fi
  done
}

apt_fix_broken() {
  info "Attempting basic dpkg/apt remediation (best-effort)..."
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
  DEBIAN_FRONTEND=noninteractive apt-get -y -f install || true
}

apt_health_gate() {
  # Aim: reduce "partial first run" by refusing to proceed when dpkg/apt is clearly unhappy.
  info "APT health gate (preflight)..."
  local audit_out=""
  audit_out="$(dpkg --audit 2>/dev/null || true)"
  if [[ -n "$audit_out" ]]; then
    warn "dpkg --audit reported issues (attempting to repair):"
    echo "$audit_out"
  fi

  apt_fix_broken

  # Basic repo sanity without touching sources yet.
  set +e
  DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Use-Pty=0 -o Acquire::Retries=2 update >/dev/null 2>&1
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    warn "apt-get update had issues before conversion. This may be corporate proxy/mirror-related."
    warn "Proceeding, but conversion success probability is reduced."
  fi

  # If dpkg is still in a bad state, stop.
  audit_out="$(dpkg --audit 2>/dev/null || true)"
  if [[ -n "$audit_out" ]]; then
    die "dpkg is still in an unhealthy state after repair attempts. Resolve dpkg/apt issues before converting."
  fi

  ok "APT health gate passed."
}

apt_opts_common() {
  local -a opts
  opts=(-y -o Dpkg::Use-Pty=0 -o Acquire::Retries=3)
  if [[ "$WITH_RECOMMENDS" != "yes" ]]; then
    opts+=(--no-install-recommends)
  fi
  echo "${opts[@]}"
}

# =========================
# OS Detection
# =========================
detect_os() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"

  info "Script v${SCRIPT_VERSION}"
  info "Log: ${LOG_FILE}"
  info "Detected OS: ${NAME:-unknown} (ID=${OS_ID}, VERSION_ID=${OS_VERSION_ID}, CODENAME=${OS_CODENAME})"

  [[ "$OS_ID" == "ubuntu" ]] || die "Unsupported OS ID '${OS_ID}'. This script supports Ubuntu bases only."

  case "${OS_CODENAME}" in
    noble)
      UBUNTU_BASE="noble"
      DEFAULT_MINT="zena"
      ALLOWED_TARGETS=(zena zara xia wilma)
      ;;
    jammy)
      UBUNTU_BASE="jammy"
      DEFAULT_MINT="virginia"
      ALLOWED_TARGETS=(virginia victoria vera vanessa)
      ;;
    *)
      die "Unsupported Ubuntu codename '${OS_CODENAME}'. Supported: noble (24.04), jammy (22.04)."
      ;;
  esac

  if [[ -z "$TARGET_MINT" ]]; then
    TARGET_MINT="$DEFAULT_MINT"
  fi

  TARGET_MINT="${TARGET_MINT,,}"
  EDITION="${EDITION,,}"

  case "$EDITION" in
    cinnamon|mate|xfce) : ;;
    *) die "Unsupported --edition '${EDITION}'. Allowed: cinnamon|mate|xfce" ;;
  esac

  # Normalize potential whitespace / CRLF
  TARGET_MINT="$(echo -n "$TARGET_MINT" | tr -d '\r' | xargs)"
  EDITION="$(echo -n "$EDITION" | tr -d '\r' | xargs)"

  local found="no"
  for t in "${ALLOWED_TARGETS[@]}"; do
    if [[ "$t" == "$TARGET_MINT" ]]; then found="yes"; break; fi
  done
  [[ "$found" == "yes" ]] || die "--target '${TARGET_MINT}' not allowed for Ubuntu '${OS_CODENAME}'. Allowed: ${ALLOWED_TARGETS[*]}"

  info "Ubuntu base: ${UBUNTU_BASE} | Target Mint codename: ${TARGET_MINT} | Edition: ${EDITION}"
}

# =========================
# Backup / Restore
# =========================
backup_system_state() {
  local backup_dir="/root/ubuntu-to-mint-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  ON_ERROR_BACKUP_HINT="Rollback suggestion: sudo bash $0 rollback ${backup_dir}"

  info "Creating backup at: ${backup_dir}"
  mkdir -p "${backup_dir}/etc"
  cp -a /etc/apt "${backup_dir}/etc/" || true
  cp -a /etc/os-release /etc/lsb-release 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/fstab /etc/hostname /etc/hosts 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/lightdm 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/X11/default-display-manager 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/systemd/system/display-manager.service 2>/dev/null "${backup_dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${backup_dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${backup_dir}/apt-manual.txt" || true
  apt-mark showhold > "${backup_dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${backup_dir}/enabled-services.txt" 2>/dev/null || true

  if have_cmd snap; then snap list > "${backup_dir}/snap-list.txt" || true; fi
  if have_cmd flatpak; then flatpak list > "${backup_dir}/flatpak-list.txt" || true; fi

  ok "Backup complete."
  echo "$backup_dir"
}

rollback() {
  need_root
  local dir="${1:-}"
  [[ -n "$dir" ]] || die "rollback requires a backup directory argument"
  [[ -d "$dir" ]] || die "backup directory not found: $dir"
  [[ -d "$dir/etc/apt" ]] || die "backup does not contain etc/apt: $dir/etc/apt"

  info "Restoring /etc/apt from: $dir/etc/apt"
  rm -rf /etc/apt
  cp -a "$dir/etc/apt" /etc/apt

  if [[ -d "$dir/disabled-sources" ]]; then
    info "Restoring disabled third-party sources from backup..."
    mkdir -p /etc/apt/sources.list.d
    cp -a "$dir/disabled-sources/"* /etc/apt/sources.list.d/ 2>/dev/null || true
  fi

  ok "Rollback APT config restored."
  info "Now run:"
  echo "  sudo apt-get update"
  echo "  sudo apt-get -f install"
}

# =========================
# Timeshift snapshot
# =========================
timeshift_snapshot_best_effort() {
  if have_cmd timeshift; then
    info "Timeshift detected. Attempting pre-change snapshot (best-effort)..."
    timeshift --create --comments "pre ubuntu->mint $(date -Is)" --tags D || warn "Timeshift snapshot failed (may not be configured)."
  else
    warn "Timeshift not installed. Strongly recommended to snapshot/backup before converting."
  fi
}

# =========================
# Keyrings
# =========================
gpg_key_file_has_keyid() {
  local f="$1"
  local keyid="$2"
  gpg --batch --with-colons --show-keys "$f" 2>/dev/null \
    | awk -F: '$1=="pub"||$1=="sub"{print toupper($5)}' \
    | grep -qx "$(echo "$keyid" | tr '[:lower:]' '[:upper:]')"
}

ubuntu_archive_keyring_path() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y ubuntu-keyring >/dev/null 2>&1 || true
  if [[ -r /usr/share/keyrings/ubuntu-archive-keyring.gpg ]]; then
    echo "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    return 0
  fi
  die "Ubuntu archive keyring not found at /usr/share/keyrings/ubuntu-archive-keyring.gpg (install ubuntu-keyring?)"
}

mint_keyring_build_from_linuxmint_keyring_deb() {
  local out_keyring="$1"
  [[ -n "$out_keyring" ]] || die "mint_keyring_build_from_linuxmint_keyring_deb: missing output path"

  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg dpkg-dev >/dev/null

  local tmpdir
  tmpdir="$(mktemp -d)"
  register_tmpdir "$tmpdir"
  chmod 700 "$tmpdir"

  local pool_https="https://packages.linuxmint.com/pool/main/l/linuxmint-keyring/"
  local pool_http="http://packages.linuxmint.com/pool/main/l/linuxmint-keyring/"
  local index=""

  info "Bootstrapping Mint keyring from linuxmint-keyring (.deb) pool..."
  if index="$(curl -fsSL "$pool_https" 2>/dev/null)"; then
    :
  elif index="$(curl -fsSL "$pool_http" 2>/dev/null)"; then
    :
  else
    die "Unable to fetch linuxmint-keyring pool index (blocked network/proxy?)"
  fi

  local debs
  debs="$(printf '%s' "$index" | grep -oE 'linuxmint-keyring_[0-9][^"]*_all\.deb' | sort -Vu | uniq || true)"
  [[ -n "$debs" ]] || die "Could not find linuxmint-keyring_*.deb in pool index."

  local deb
  deb="$(printf '%s\n' "$debs" | tail -n 1)"
  info "Selected linuxmint-keyring package: $deb"

  local deb_url=""
  if curl -fsI "${pool_https}${deb}" >/dev/null 2>&1; then
    deb_url="${pool_https}${deb}"
  else
    deb_url="${pool_http}${deb}"
  fi

  curl -fSL "$deb_url" -o "${tmpdir}/${deb}" || die "Failed to download ${deb_url}"

  mkdir -p "${tmpdir}/extract"
  dpkg-deb -x "${tmpdir}/${deb}" "${tmpdir}/extract"

  local -a candidates=()
  while IFS= read -r f; do candidates+=("$f"); done < <(
    find "${tmpdir}/extract" -type f \( -name '*.gpg' -o -name '*.asc' -o -name '*.key' \) 2>/dev/null | sort
  )
  [[ ${#candidates[@]} -gt 0 ]] || die "No key candidates found inside linuxmint-keyring deb."

  local chosen=""
  for f in "${candidates[@]}"; do
    if gpg_key_file_has_keyid "$f" "$MINT_KEYID"; then
      chosen="$f"
      break
    fi
  done
  [[ -n "$chosen" ]] || die "None of the candidate key files contained keyid ${MINT_KEYID}."

  mkdir -p "$(dirname "$out_keyring")"

  local tmp_out
  tmp_out="$(mktemp "${tmpdir}/keyring.XXXXXX")"
  rm -f "$tmp_out"

  info "Using key candidate: $chosen"
  if [[ "$chosen" == *.asc || "$chosen" == *.key ]]; then
    grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$chosen" 2>/dev/null || die "Selected key candidate is not armored PGP: $chosen"
    gpg --batch --dearmor -o "$tmp_out" "$chosen"
  else
    cp -a "$chosen" "$tmp_out"
  fi

  gpg_key_file_has_keyid "$tmp_out" "$MINT_KEYID" || die "Built keyring does not contain ${MINT_KEYID}"

  rm -f "$out_keyring"
  install -m 0644 "$tmp_out" "$out_keyring"

  ok "Mint repo keyring written: $out_keyring (contains ${MINT_KEYID})"
}

mint_repo_key_install_system() {
  local keyring="$SYSTEM_KEYRING"
  info "Installing Linux Mint repo signing key into ${keyring}"

  if [[ -f "$keyring" ]]; then
    if gpg_key_file_has_keyid "$keyring" "$MINT_KEYID"; then
      ok "Keyring already exists and contains ${MINT_KEYID}."
      return 0
    fi

    if [[ "$ASSUME_YES" == "yes" ]]; then
      local bkp="/root/ubuntu2mint-linuxmint-repo-keyring-backup-$(date +%Y%m%d-%H%M%S).gpg"
      warn "Existing keyring does not contain expected key; backing up to ${bkp} then overwriting due to --yes."
      cp -a "$keyring" "$bkp" 2>/dev/null || true
      rm -f "$keyring"
    else
      warn "Existing keyring at ${keyring} does not contain expected key ${MINT_KEYID}."
      warn "Re-run with --yes to overwrite automatically, or delete it manually and re-run."
      die "Keyring mismatch; refusing to proceed without explicit overwrite."
    fi
  fi

  mint_keyring_build_from_linuxmint_keyring_deb "$keyring"
}

# =========================
# APT sources + pinning
# =========================
detect_ubuntu_mirrors() {
  UBUNTU_ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
  UBUNTU_SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

  local first_archive=""
  first_archive="$(grep -RhoE 'deb (http|https)://[^ ]+/ubuntu' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head -n1 | awk '{print $2}' || true)"
  if [[ -n "$first_archive" ]]; then
    UBUNTU_ARCHIVE_MIRROR="$first_archive"
  fi

  local first_security=""
  first_security="$(grep -RhoE 'deb (http|https)://security\.ubuntu\.com/ubuntu' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head -n1 | awk '{print $2}' || true)"
  if [[ -n "$first_security" ]]; then
    UBUNTU_SECURITY_MIRROR="$first_security"
  fi

  info "Ubuntu archive mirror:  ${UBUNTU_ARCHIVE_MIRROR}"
  info "Ubuntu security mirror: ${UBUNTU_SECURITY_MIRROR}"
}

write_mint_sources_system() {
  local list="/etc/apt/sources.list.d/official-package-repositories.list"
  local mint_keyring="$SYSTEM_KEYRING"
  local ubuntu_keyring
  ubuntu_keyring="$(ubuntu_archive_keyring_path)"

  detect_ubuntu_mirrors

  info "Writing Mint+Ubuntu sources to ${list}"
  cat > "$list" <<EOF
# Do not edit this file manually.
# Generated by ubuntu-to-mint-convert-v3.sh on $(date -Is)
#
# Linux Mint repository:
deb [signed-by=${mint_keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport

# Ubuntu base repositories:
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^[[:space:]]*deb /# deb /' /etc/apt/sources.list || true
    sed -i 's/^[[:space:]]*deb-src /# deb-src /' /etc/apt/sources.list || true
  fi

  ok "Sources written."
}

write_mint_pinning_system() {
  local pref="/etc/apt/preferences.d/50-linuxmint-conversion.pref"
  info "Writing APT pinning to ${pref}"

  cat > "$pref" <<'EOF'
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 500

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700

Package: cinnamon* nemo* muffin* cjs* xapp* xapps* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700
EOF

  ok "Pinning written."
}

disable_thirdparty_sources_system() {
  local backup_dir="$1"
  local disabled_dir="${backup_dir}/disabled-sources"
  mkdir -p "$disabled_dir"

  if [[ "$KEEP_PPAS" == "yes" ]]; then
    warn "--keep-ppas set; leaving third-party sources enabled."
    return 0
  fi

  info "Disabling 3rd-party sources into: ${disabled_dir}"
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ "$(basename "$f")" == "official-package-repositories.list" ]] && continue
    mv -v "$f" "${disabled_dir}/" || true
  done
  shopt -u nullglob

  ok "Third-party sources disabled (restorable via rollback)."
}

# =========================
# LightDM / Session defaults
# =========================
session_name_for_edition() {
  case "$EDITION" in
    cinnamon) echo "cinnamon";;
    mate) echo "mate";;
    xfce) echo "xfce";;
    *) echo "cinnamon";;
  esac
}

verify_session_desktop_exists() {
  local sess="$1"
  local f="/usr/share/xsessions/${sess}.desktop"
  if [[ -f "$f" ]]; then
    ok "Session desktop present: $f"
    return 0
  fi
  warn "Expected session desktop missing: $f"
  return 1
}

force_display_manager_symlink() {
  # Enforce /etc/systemd/system/display-manager.service -> lightdm.service when possible.
  if [[ -d /run/systemd/system ]]; then
    if [[ -f /lib/systemd/system/lightdm.service ]]; then
      mkdir -p /etc/systemd/system
      ln -sf /lib/systemd/system/lightdm.service /etc/systemd/system/display-manager.service || true
    fi
  fi
}

ensure_lightdm_on_boot() {
  if [[ ! -d /run/systemd/system ]]; then
    warn "systemd not detected; cannot enable LightDM on boot in this environment."
    return 0
  fi

  info "Ensuring LightDM starts on boot (graphical.target + display-manager.service)..."

  DEBIAN_FRONTEND=noninteractive apt-get install -y lightdm slick-greeter >/dev/null 2>&1 || true

  # Unmask anything that could block startup
  systemctl unmask lightdm.service >/dev/null 2>&1 || true
  systemctl unmask display-manager.service >/dev/null 2>&1 || true

  # Boot to graphical target
  systemctl set-default graphical.target >/dev/null 2>&1 || true
  systemctl enable graphical.target >/dev/null 2>&1 || true

  # Default display manager selection (Debian/Ubuntu mechanism)
  echo "/usr/sbin/lightdm" > /etc/X11/default-display-manager || true
  if have_cmd update-alternatives; then
    update-alternatives --set x-display-manager /usr/sbin/lightdm >/dev/null 2>&1 || true
  fi

  # If GDM exists, disable it so it can't steal the login screen
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'gdm3.service'; then
    systemctl disable --now gdm3.service >/dev/null 2>&1 || true
    systemctl mask gdm3.service >/dev/null 2>&1 || true
  fi

  # Ensure the display-manager alias points to lightdm
  force_display_manager_symlink

  systemctl daemon-reload >/dev/null 2>&1 || true

  # Enable display-manager.service (the alias most systems rely on)
  systemctl enable display-manager.service >/dev/null 2>&1 || true

  # lightdm.service may be "static" on some Ubuntu builds; enabling may be a no-op (fine)
  systemctl enable lightdm.service >/dev/null 2>&1 || true

  # Try to (re)enable links if previously swapped
  systemctl reenable display-manager.service >/dev/null 2>&1 || true
  systemctl reenable lightdm.service >/dev/null 2>&1 || true

  # Start now (best-effort)
  systemctl restart display-manager.service >/dev/null 2>&1 || true
  systemctl restart lightdm.service >/dev/null 2>&1 || true

  ok "LightDM configured to start on boot."
}

ensure_lightdm_defaults() {
  local sess
  sess="$(session_name_for_edition)"

  info "Configuring LightDM defaults for edition=${EDITION} (session=${sess})"
  DEBIAN_FRONTEND=noninteractive apt-get install -y lightdm slick-greeter

  mkdir -p /etc/lightdm/lightdm.conf.d

  # Comment out any existing user-session settings (keep files)
  shopt -s nullglob
  for f in /etc/lightdm/lightdm.conf.d/*.conf; do
    [[ "$(basename "$f")" == "99-ubuntu2mint.conf" ]] && continue
    if grep -qE '^[[:space:]]*user-session=' "$f" 2>/dev/null; then
      warn "Found existing user-session setting in $f; commenting it out (keeping file)."
      sed -i 's/^[[:space:]]*user-session=/# user-session=/' "$f" || true
    fi
  done
  shopt -u nullglob

  cat > /etc/lightdm/lightdm.conf.d/99-ubuntu2mint.conf <<EOF
# Generated by ubuntu-to-mint-convert-v3.sh on $(date -Is)
[Seat:*]
greeter-session=slick-greeter
user-session=${sess}
EOF

  # Set default session for users
  for homedir in /home/*; do
    [[ -d "$homedir" ]] || continue
    local user
    user="$(basename "$homedir")"
    [[ "$user" == "lost+found" ]] && continue

    local dmrc="${homedir}/.dmrc"
    if [[ ! -f "$dmrc" ]]; then
      cat > "$dmrc" <<EOF
[Desktop]
Session=${sess}
EOF
      chown "${user}:${user}" "$dmrc" 2>/dev/null || true
      chmod 644 "$dmrc" || true
      continue
    fi

    if grep -q '^\[Desktop\]' "$dmrc"; then
      if grep -q '^Session=' "$dmrc"; then
        sed -i "s/^Session=.*/Session=${sess}/" "$dmrc" || true
      else
        sed -i "/^\[Desktop\]/a Session=${sess}" "$dmrc" || true
      fi
    else
      printf "\n[Desktop]\nSession=%s\n" "$sess" >> "$dmrc"
    fi
    chown "${user}:${user}" "$dmrc" 2>/dev/null || true
    chmod 644 "$dmrc" || true
  done

  verify_session_desktop_exists "$sess" || true
  ensure_lightdm_on_boot
  ok "LightDM defaults applied; default session set to ${sess}."
}

# =========================
# Mintupdate icon conflict mitigation
# =========================
apply_mintupdate_icon_diversion() {
  local f="/usr/share/icons/hicolor/16x16/apps/software-properties.png"
  if [[ -f "$f" ]]; then
    if dpkg -S "$f" 2>/dev/null | grep -q '^software-properties-gtk:'; then
      if ! dpkg-divert --list "$f" 2>/dev/null | grep -q "$f"; then
        warn "Applying dpkg-divert to avoid mintupdate vs software-properties-gtk file conflict: $f"
        dpkg-divert --package ubuntu2mint --add --rename --divert "${f}.ubuntu2mint" "$f" || true
      fi
    fi
  fi
}

# =========================
# Post-install sanity checks
# =========================
post_install_sanity() {
  local out_file="${1:-/tmp/post-convert-validation.txt}"
  mkdir -p "$(dirname "$out_file")" 2>/dev/null || true

  {
    echo "Post-conversion validation ($(date -Is))"
    echo "======================================"
    echo
    echo "OS release:"
    cat /etc/os-release || true
    echo
    echo "Keyring contains ${MINT_KEYID}:"
    if [[ -f "$SYSTEM_KEYRING" ]] && gpg_key_file_has_keyid "$SYSTEM_KEYRING" "$MINT_KEYID"; then
      echo "OK"
    else
      echo "FAIL"
    fi
    echo
    echo "Boot/display settings:"
    echo "default-display-manager: $(cat /etc/X11/default-display-manager 2>/dev/null || echo MISSING)"
    echo "default target: $(systemctl get-default 2>/dev/null || echo unknown)"
    echo "lightdm enabled: $(systemctl is-enabled lightdm.service 2>/dev/null || echo unknown)"
    echo "display-manager enabled: $(systemctl is-enabled display-manager.service 2>/dev/null || echo unknown)"
    echo "gdm3 enabled: $(systemctl is-enabled gdm3.service 2>/dev/null || echo not-installed)"
    echo
    echo "display-manager.service link:"
    ls -l /etc/systemd/system/display-manager.service 2>/dev/null || true
    echo
  } > "$out_file"

  ok "Post-conversion validation written: $out_file"
}

validate_desktop_session_runtime() {
  local sess
  sess="$(session_name_for_edition)"

  info "Desktop session diagnostics (non-fatal)..."
  verify_session_desktop_exists "$sess" || true

  case "$EDITION" in
    cinnamon)
      have_cmd cinnamon-session || warn "Missing command: cinnamon-session (Cinnamon logins may fail)."
      have_cmd muffin || warn "Missing command: muffin (Cinnamon compositor)."
      if [[ -x /usr/bin/csd-power ]]; then
        if /usr/bin/csd-power --help >/dev/null 2>&1; then
          ok "csd-power runs (basic)."
        else
          warn "csd-power appears broken (may cause Cinnamon login loop). Consider reinstalling cinnamon-settings-daemon."
        fi
      fi
      ;;
    xfce)
      have_cmd xfce4-session || warn "Missing command: xfce4-session."
      ;;
    mate)
      have_cmd mate-session || warn "Missing command: mate-session."
      ;;
  esac
}

# =========================
# Install stack with retry (reduces "first run partial, second run completes")
# =========================
install_mint_stack_with_retry() {
  local meta="$1"
  shift || true

  local -a pkgs=(
    "$meta"
    mint-meta-core
    mintsystem
    mintupdate
    mintsources
    mint-meta-codecs
  )

  apply_mintupdate_icon_diversion

  local attempt rc
  for attempt in 1 2; do
    info "Installing Mint stack (attempt ${attempt}/2)..."
    set +e
    DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) install "${pkgs[@]}"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      ok "Mint stack installed successfully."
      return 0
    fi

    warn "Mint stack install attempt ${attempt} failed (exit ${rc}). Running remediation then retrying..."
    apply_mintupdate_icon_diversion
    apt_fix_broken
    DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) update || true
  done

  die "Unable to install Mint stack after retry. See log: ${LOG_FILE}"
}

# =========================
# Plan mode helpers
# =========================
apt_tmp_run() {
  local tmpapt="$1"; shift
  local -a extra=(
    -o "Dir=${tmpapt}"
    -o "Dir::State::status=/var/lib/dpkg/status"
    -o "Dir::Etc::sourcelist=${tmpapt}/etc/apt/sources.list"
    -o "Dir::Etc::sourceparts=${tmpapt}/etc/apt/sources.list.d"
    -o "Dir::Etc::preferencesparts=${tmpapt}/etc/apt/preferences.d"
    -o "Dir::Cache=${tmpapt}/var/cache/apt"
    -o "Dir::State=${tmpapt}/var/lib/apt"
    -o "Dir::State::Lists=${tmpapt}/var/lib/apt/lists"
    -o "APT::Sandbox::User=_apt"
  )
  apt-get "${extra[@]}" "$@"
}

plan_fix_tmpapt_perms() {
  local tmpapt="$1"

  chmod 755 "$tmpapt" 2>/dev/null || true
  chmod 755 "$tmpapt"/{etc,usr,var} 2>/dev/null || true
  chmod 755 "$tmpapt"/var/{lib,cache} 2>/dev/null || true
  chmod 755 "$tmpapt"/var/lib/apt 2>/dev/null || true
  chmod 755 "$tmpapt"/var/cache/apt 2>/dev/null || true

  if id _apt >/dev/null 2>&1; then
    if [[ -d "$tmpapt/var/lib/apt/lists/partial" ]]; then
      chown -R _apt:root "$tmpapt/var/lib/apt/lists/partial" 2>/dev/null || true
      chmod 755 "$tmpapt/var/lib/apt/lists/partial" 2>/dev/null || true
    fi
    if [[ -d "$tmpapt/var/cache/apt/archives/partial" ]]; then
      chown -R _apt:root "$tmpapt/var/cache/apt/archives/partial" 2>/dev/null || true
      chmod 755 "$tmpapt/var/cache/apt/archives/partial" 2>/dev/null || true
    fi
    # Ensure lists/archives roots are readable by _apt
    chown -R _apt:root "$tmpapt/var/lib/apt/lists" "$tmpapt/var/cache/apt/archives" 2>/dev/null || true
  fi
}

plan_mode() {
  need_root
  check_deps "yes"
  ensure_no_apt_locks
  detect_os
  check_disk_space_gb 2 hard

  info "Running plan mode (dry-run) with temporary APT root..."

  local tmpapt
  tmpapt="$(mktemp -d)"
  register_tmpdir "$tmpapt"

  mkdir -p "${tmpapt}/etc/apt/sources.list.d" \
           "${tmpapt}/etc/apt/preferences.d" \
           "${tmpapt}/var/lib/apt/lists/partial" \
           "${tmpapt}/var/cache/apt/archives/partial" \
           "${tmpapt}/usr/share/keyrings"

  plan_fix_tmpapt_perms "$tmpapt"

  local tmp_keyring="${tmpapt}/usr/share/keyrings/linuxmint-repo.gpg"
  mint_keyring_build_from_linuxmint_keyring_deb "$tmp_keyring"

  local ubuntu_keyring
  ubuntu_keyring="$(ubuntu_archive_keyring_path)"

  detect_ubuntu_mirrors

  cat > "${tmpapt}/etc/apt/sources.list" <<EOF
deb [signed-by=${tmp_keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport

deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb [signed-by=${ubuntu_keyring}] ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  cat > "${tmpapt}/etc/apt/preferences.d/50-linuxmint-conversion.pref" <<'EOF'
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 500

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700

Package: cinnamon* nemo* muffin* cjs* xapp* xapps* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700
EOF

  info "APT update (plan)..."
  apt_tmp_run "$tmpapt" update -y >/dev/null

  local meta=""
  case "$EDITION" in
    cinnamon) meta="mint-meta-cinnamon" ;;
    mate) meta="mint-meta-mate" ;;
    xfce) meta="mint-meta-xfce" ;;
  esac

  local plan_out="${LOG_DIR}/plan-$(date +%Y%m%d-%H%M%S).txt"
  info "Simulating install (plan) -> ${plan_out}"

  set +e
  apt_tmp_run "$tmpapt" -s install $(apt_opts_common) \
    "$meta" mint-meta-core mintsystem mintupdate mintsources mint-meta-codecs \
    2>&1 | tee "$plan_out"
  local rc=${PIPESTATUS[0]}
  set -e

  if [[ $rc -ne 0 ]]; then
    warn "Plan simulation failed (exit $rc). Review: $plan_out"
    exit $rc
  fi

  ok "Plan completed successfully. Review: $plan_out"
}

# =========================
# Doctor
# =========================
doctor() {
  need_root
  check_deps "${ASSUME_YES}"
  ensure_no_apt_locks
  detect_os
  check_disk_space_gb 2 warn

  info "Doctor checks..."
  apt_fix_broken

  local holds
  holds="$(apt-mark showhold || true)"
  if [[ -n "$holds" ]]; then
    warn "Held packages detected (could interfere with conversion):"
    echo "$holds"
  else
    ok "No held packages detected."
  fi

  ok "Doctor complete."
}

# =========================
# Convert
# =========================
show_disclaimer_and_require_ack() {
  if [[ "$I_ACCEPT_RISK" != "yes" ]]; then
    die "convert requires --i-accept-the-risk"
  fi

  if ! is_tty; then
    if [[ "$ASSUME_YES" == "yes" ]]; then
      warn "Non-interactive session detected; proceeding due to --yes and --i-accept-the-risk."
      return 0
    fi
    die "convert in non-interactive mode requires --yes (in addition to --i-accept-the-risk)"
  fi

  if [[ "$ASSUME_YES" == "yes" ]]; then
    warn "Skipping interactive disclaimer prompt due to --yes."
    return 0
  fi

  echo
  echo "${RED}${BOLD}*** UNSUPPORTED / HIGH-RISK MIGRATION ***${RESET}"
  echo "${RED}${BOLD}This is an IN-PLACE Ubuntu -> Mint-like conversion and is NOT supported.${RESET}"
  echo "${RED}${BOLD}It may break VPN/EDR/MDM, compliance posture, and system stability.${RESET}"
  echo "${RED}${BOLD}A CLEAN INSTALL is strongly recommended instead.${RESET}"
  echo
  echo "Type: ${BOLD}I UNDERSTAND${RESET} to continue, or anything else to abort:"
  read -r ack
  [[ "$ack" == "I UNDERSTAND" ]] || die "User aborted."
}

convert() {
  need_root
  check_deps "yes"
  ensure_no_apt_locks
  detect_os
  check_disk_space_gb 6 hard
  show_disclaimer_and_require_ack

  # Make first run succeed more often:
  apt_health_gate

  local backup_dir
  backup_dir="$(backup_system_state)"
  disable_thirdparty_sources_system "$backup_dir"
  timeshift_snapshot_best_effort

  # Deterministic repo verification:
  mint_repo_key_install_system
  write_mint_sources_system
  write_mint_pinning_system

  info "APT update..."
  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) update

  local meta=""
  case "$EDITION" in
    cinnamon) meta="mint-meta-cinnamon" ;;
    mate) meta="mint-meta-mate" ;;
    xfce) meta="mint-meta-xfce" ;;
  esac

  install_mint_stack_with_retry "$meta"

  if [[ "$PRESERVE_SNAP" == "yes" ]]; then
    info "Preserving snap support (best-effort)..."
    DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) install snapd || true
  fi

  # Fix: /etc/X11/Xsession.d/* has_option command not found
  info "Reinstalling x11-common (fixes Xsession has_option issues)..."
  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) install --reinstall x11-common || true

  # Apply LightDM defaults AFTER the desktop is installed
  ensure_lightdm_defaults

  validate_desktop_session_runtime || true

  mkdir -p "$backup_dir" 2>/dev/null || true
  post_install_sanity "${backup_dir}/post-convert-validation.txt" || true

  ok "Conversion steps completed."
  info "Backup dir: ${backup_dir}"
  info "Recommended next steps:"
  echo "  1) Reboot"
  echo "  2) At LightDM, select '${EDITION}' session if needed"
  echo "  3) Validate VPN/EDR/MDM tooling and compliance"
}

# =========================
# Parse args in any order
# =========================
parse_args_any_order() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      doctor|plan|convert|rollback)
        if [[ -n "$CMD" ]]; then
          die "Multiple commands specified: '${CMD}' and '$1'"
        fi
        CMD="$1"
        shift 1
        if [[ "$CMD" == "rollback" ]]; then
          if [[ $# -gt 0 && "${1:-}" != --* ]]; then
            ROLLBACK_DIR="$1"
            shift 1
          fi
        fi
        ;;
      --edition) EDITION="${2:-}"; shift 2;;
      --target) TARGET_MINT="${2:-}"; shift 2;;
      --mint-mirror) MINT_MIRROR="${2:-}"; shift 2;;
      --keep-ppas) KEEP_PPAS="yes"; shift 1;;
      --preserve-snap) PRESERVE_SNAP="yes"; shift 1;;
      --with-recommends) WITH_RECOMMENDS="yes"; shift 1;;
      --yes) ASSUME_YES="yes"; shift 1;;
      --i-accept-the-risk) I_ACCEPT_RISK="yes"; shift 1;;
      -h|--help|help) usage; exit 0;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

# =========================
# Main
# =========================
main() {
  parse_args_any_order "$@"
  [[ -n "$CMD" ]] || { usage; exit 1; }

  case "$CMD" in
    doctor) doctor ;;
    plan) plan_mode ;;
    convert) convert ;;
    rollback)
      [[ -n "$ROLLBACK_DIR" ]] || die "rollback requires a directory argument"
      rollback "$ROLLBACK_DIR"
      ;;
    *) die "Unknown command: $CMD" ;;
  esac
}

main "$@"
