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
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# ubuntu2mint: Ubuntu base + Mint repo + Mint desktop/tooling (best-effort)
# NOTE: This does NOT create a supported Linux Mint OS. Ubuntu remains the base.
###############################################################################

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="4.5"

LOG_DIR="/var/log/ubuntu-to-mint"
DEFAULT_MINT_MIRROR="http://packages.linuxmint.com"

KEYRING_OUT="/usr/share/keyrings/linuxmint-repo.gpg"
SOURCES_OUT="/etc/apt/sources.list.d/official-package-repositories.list"
PIN_BASE_OUT="/etc/apt/preferences.d/50-linuxmint-conversion.pref"
PIN_STACK_OUT="/etc/apt/preferences.d/51-linuxmint-desktop-stack.pref"
SNAP_PREF_OUT="/etc/apt/preferences.d/99-ubuntu2mint-snap.pref"
LIGHTDM_PREF_OUT="/etc/lightdm/lightdm.conf.d/90-ubuntu2mint.conf"

MAX_ALLOWED_REMOVALS_DEFAULT=40

# runtime vars (always initialized for set -u safety)
SUBCMD="${1:-}"
shift || true

UBUNTU_BASE=""
DEFAULT_MINT=""
ALLOWED_TARGETS=()        # IMPORTANT: array to avoid IFS splitting bug
TARGET_MINT=""
EDITION="cinnamon"
MINT_MIRROR="$DEFAULT_MINT_MIRROR"

KEEP_PPAS="no"
PRESERVE_SNAP="yes"
WITH_RECOMMENDS="no"
ASSUME_YES="no"
RISK_ACK_FLAG="no"
OVERWRITE_KEYRING="no"
RECREATE_KEYRING="no"
AUTO_FIX="yes"
PURGE_CONFLICTING_FLAVORS="yes"
MAX_ALLOWED_REMOVALS="$MAX_ALLOWED_REMOVALS_DEFAULT"

BACKUP_DIR=""
ON_ERROR_BACKUP_HINT=""
LOG_FILE=""

###############################################################################
# Pretty output helpers
###############################################################################
is_tty() { [[ -t 1 ]]; }

c_reset=""; c_red=""; c_grn=""; c_ylw=""; c_blu=""; c_bold=""
if is_tty; then
  c_reset="$(printf '\033[0m')"
  c_red="$(printf '\033[31m')"
  c_grn="$(printf '\033[32m')"
  c_ylw="$(printf '\033[33m')"
  c_blu="$(printf '\033[34m')"
  c_bold="$(printf '\033[1m')"
fi

ts() { date -Is; }
info() { echo "${c_blu}INFO:${c_reset}  $*"; }
ok()   { echo "${c_grn}OK:${c_reset}    $*"; }
warn() { echo "${c_ylw}WARN:${c_reset}  $*"; }
err()  { echo "${c_red}ERROR:${c_reset} $*"; }

die() {
  err "$*"
  [[ -n "${ON_ERROR_BACKUP_HINT:-}" ]] && echo -e "\nRollback hint: ${ON_ERROR_BACKUP_HINT}"
  exit 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

###############################################################################
# Logging + traps
###############################################################################
setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/ubuntu-to-mint-$(date +%Y%m%d-%H%M%S).log"
  exec > >(tee -a "$LOG_FILE") 2>&1
  info "Script v${SCRIPT_VERSION}"
  info "Log: ${LOG_FILE}"
}

on_err() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-?}
  local cmd=${BASH_COMMAND:-?}
  err "FAILED at line ${line_no} (exit ${exit_code})."
  err "Command: ${cmd}"
  [[ -n "${LOG_FILE:-}" ]] && err "Log: ${LOG_FILE}"
  [[ -n "${ON_ERROR_BACKUP_HINT:-}" ]] && echo -e "\nRollback hint: ${ON_ERROR_BACKUP_HINT}"
  exit "$exit_code"
}
trap on_err ERR

###############################################################################
# Usage
###############################################################################
usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

High-risk, best-effort in-place "Ubuntu -> Mint desktop/tooling" graft.
Ubuntu remains the base OS; Mint repos+packages are added with pinning.

Usage:
  sudo bash ${SCRIPT_NAME} doctor
  sudo bash ${SCRIPT_NAME} plan [options]
  sudo bash ${SCRIPT_NAME} convert --i-accept-the-risk [options]
  sudo bash ${SCRIPT_NAME} rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS

Options:
  --edition cinnamon|mate|xfce     (default: cinnamon)
  --target <mint_codename>         Override Mint target codename (validated per Ubuntu base)
  --mint-mirror <url>              (default: ${DEFAULT_MINT_MIRROR})

  --keep-ppas                      Do NOT disable third-party APT sources (not recommended)
  --preserve-snap / --no-preserve-snap   (default: preserve snap)
  --with-recommends                Allow recommended packages during install (default: off)
  --yes                            Skip most prompts (convert still requires disclaimer gate + --i-accept-the-risk)
  --max-removals N                 Abort if APT simulation removes more than N packages (default: ${MAX_ALLOWED_REMOVALS_DEFAULT})

  --overwrite-keyring              If ${KEYRING_OUT} exists, overwrite it
  --recreate-keyring               Backup+delete ${KEYRING_OUT} then recreate it

  --no-auto-fix                    Do not attempt dpkg/apt repair pre-flight
  --no-purge-flavor                Do not purge conflicting Ubuntu-flavor packages (ubuntucinnamon*, etc.)

Notes:
  * Conversion configures LightDM + slick-greeter and defaults the session to your chosen --edition.
  * LightDM implies X11 session by default. This script does not attempt Wayland defaults.
EOF
}

###############################################################################
# Argument parsing
###############################################################################
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --edition) EDITION="${2:-}"; shift 2 ;;
      --target) TARGET_MINT="${2:-}"; shift 2 ;;
      --mint-mirror) MINT_MIRROR="${2:-}"; shift 2 ;;
      --keep-ppas) KEEP_PPAS="yes"; shift ;;
      --preserve-snap) PRESERVE_SNAP="yes"; shift ;;
      --no-preserve-snap) PRESERVE_SNAP="no"; shift ;;
      --with-recommends) WITH_RECOMMENDS="yes"; shift ;;
      --yes) ASSUME_YES="yes"; shift ;;
      --i-accept-the-risk) RISK_ACK_FLAG="yes"; shift ;;
      --overwrite-keyring) OVERWRITE_KEYRING="yes"; shift ;;
      --recreate-keyring) RECREATE_KEYRING="yes"; shift ;;
      --no-auto-fix) AUTO_FIX="no"; shift ;;
      --no-purge-flavor) PURGE_CONFLICTING_FLAVORS="no"; shift ;;
      --max-removals) MAX_ALLOWED_REMOVALS="${2:-}"; shift 2 ;;
      -h|--help|help) usage; exit 0 ;;
      *) die "Unknown argument: $1 (use --help)" ;;
    esac
  done

  case "$EDITION" in
    cinnamon|mate|xfce) : ;;
    *) die "--edition must be cinnamon|mate|xfce" ;;
  esac

  [[ "$MAX_ALLOWED_REMOVALS" =~ ^[0-9]+$ ]] || die "--max-removals must be an integer"
}

###############################################################################
# APT option builder (array-safe; does NOT rely on IFS splitting)
###############################################################################
apt_get_opts_common() {
  local -n _out="$1"
  _out=(
    "-y"
    "-o" "Dpkg::Use-Pty=0"
    "-o" "APT::Color=1"
    "-o" "Acquire::Retries=3"
  )
  if [[ "$WITH_RECOMMENDS" == "no" ]]; then
    _out+=("--no-install-recommends")
  fi
}

apt_get_opts_force_overwrite() {
  local -n _out="$1"
  apt_get_opts_common _out
  _out+=(
    "-o" "Dpkg::Options::=--force-overwrite"
    "-o" "Dpkg::Options::=--force-confnew"
  )
}

###############################################################################
# System checks
###############################################################################
require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (use sudo)."; }

check_apt_locks() {
  local locks=(
    "/var/lib/dpkg/lock"
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/apt/lists/lock"
    "/var/cache/apt/archives/lock"
  )
  for l in "${locks[@]}"; do
    if [[ -e "$l" ]] && fuser "$l" >/dev/null 2>&1; then
      die "APT/dpkg lock active on ${l}. Close Software Updater/apt/dpkg and retry."
    fi
  done
}

detect_os() {
  [[ -r /etc/os-release ]] || die "Missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  local id="${ID:-}"
  local ver="${VERSION_ID:-}"
  local codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"

  info "Detected OS: ${NAME:-unknown} (ID=${id}, VERSION_ID=${ver}, CODENAME=${codename})"

  [[ "$id" == "ubuntu" ]] || die "This script only supports Ubuntu as the base (ID=ubuntu)."

  case "$codename" in
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
      die "Unsupported Ubuntu codename '${codename}'. Supported: noble (24.04), jammy (22.04)."
      ;;
  esac

  if [[ -z "$TARGET_MINT" ]]; then
    TARGET_MINT="$DEFAULT_MINT"
  fi

  local ok_target="no"
  local t=""
  for t in "${ALLOWED_TARGETS[@]}"; do
    if [[ "$TARGET_MINT" == "$t" ]]; then
      ok_target="yes"
      break
    fi
  done

  [[ "$ok_target" == "yes" ]] || die "--target '${TARGET_MINT}' not allowed for Ubuntu '${UBUNTU_BASE}'. Allowed: ${ALLOWED_TARGETS[*]}"
  info "Ubuntu base: ${UBUNTU_BASE} | Target Mint codename: ${TARGET_MINT} | Edition: ${EDITION}"
}

###############################################################################
# Risk disclaimer (convert only)
###############################################################################
convert_disclaimer_gate() {
  [[ "$SUBCMD" == "convert" ]] || return 0

  if [[ "$RISK_ACK_FLAG" != "yes" ]]; then
    die "convert requires --i-accept-the-risk"
  fi

  # Required interaction even with --yes (user explicitly requested this)
  if ! is_tty; then
    die "convert requires an interactive TTY to acknowledge the disclaimer."
  fi

  echo
  echo "${c_red}${c_bold}##############################################${c_reset}"
  echo "${c_red}${c_bold}#  UNSUPPORTED MIGRATION (READ CAREFULLY)    #${c_reset}"
  echo "${c_red}${c_bold}##############################################${c_reset}"
  echo "${c_red}${c_bold}This script performs an IN-PLACE graft: Ubuntu stays the base OS.${c_reset}"
  echo "${c_red}${c_bold}It adds Linux Mint repositories + Mint desktop/tooling.${c_reset}"
  echo
  echo "${c_red}${c_bold}This is UNSUPPORTED and (frankly) probably dumb to do on a real workstation.${c_reset}"
  echo "${c_red}${c_bold}Corporate EDR/MDM/VPN/compliance tooling may break and require re-enrollment.${c_reset}"
  echo "${c_red}${c_bold}A clean install is strongly recommended instead.${c_reset}"
  echo
  echo "To continue, type exactly: ${c_bold}I UNDERSTAND${c_reset}"
  echo -n "> "
  local resp=""
  read -r resp
  if [[ "$resp" != "I UNDERSTAND" ]]; then
    die "Disclaimer not acknowledged. Aborting."
  fi
  ok "Disclaimer acknowledged."
}

###############################################################################
# APT / dpkg repair
###############################################################################
apt_fix_basic() {
  info "Attempting basic dpkg/apt repair (best-effort)..."
  export DEBIAN_FRONTEND=noninteractive
  dpkg --configure -a || true
  apt-get -y -f install || true
  apt-get -y --fix-broken install || true
  apt-get -y update || true
  ok "Basic repair attempt complete."
}

doctor_report() {
  info "Doctor checks:"
  check_apt_locks

  local holds=""
  holds="$(apt-mark showhold 2>/dev/null || true)"
  if [[ -n "$holds" ]]; then
    warn "Held packages detected:"
    echo "$holds"
  else
    ok "No held packages detected."
  fi

  if dpkg --audit | grep -q .; then
    warn "dpkg reports issues:"
    dpkg --audit || true
  else
    ok "dpkg --audit clean."
  fi

  if apt-get -s check >/dev/null 2>&1; then
    ok "apt-get check: OK"
  else
    warn "apt-get check reports problems."
  fi

  ok "Doctor complete."
}

###############################################################################
# Backup / rollback
###############################################################################
backup_system_state() {
  local backup_dir="/root/ubuntu-to-mint-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  ON_ERROR_BACKUP_HINT="sudo bash $SCRIPT_NAME rollback ${backup_dir}"

  info "Creating backup at: ${backup_dir}"
  mkdir -p "${backup_dir}/etc"
  cp -a /etc/apt "${backup_dir}/etc/" || true
  cp -a /etc/os-release /etc/lsb-release 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/fstab /etc/hostname /etc/hosts 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/lightdm 2>/dev/null "${backup_dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${backup_dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${backup_dir}/apt-manual.txt" || true
  apt-mark showhold > "${backup_dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${backup_dir}/enabled-services.txt" || true

  if have_cmd snap; then snap list > "${backup_dir}/snap-list.txt" || true; fi
  if have_cmd flatpak; then flatpak list > "${backup_dir}/flatpak-list.txt" || true; fi

  # Always create the post-validation report placeholder so callers never fail on missing file
  : > "${backup_dir}/post-convert-validation.txt" || true

  ok "Backup complete."
  echo "$backup_dir"
}

restore_backup() {
  local backup_dir="$1"
  [[ -d "$backup_dir" ]] || die "Backup directory not found: $backup_dir"
  [[ -d "${backup_dir}/etc/apt" ]] || die "Backup missing etc/apt: ${backup_dir}/etc/apt"

  info "Restoring /etc/apt from backup..."
  rm -rf /etc/apt
  cp -a "${backup_dir}/etc/apt" /etc/apt

  if [[ -d "${backup_dir}/etc/lightdm" ]]; then
    info "Restoring /etc/lightdm from backup..."
    rm -rf /etc/lightdm
    cp -a "${backup_dir}/etc/lightdm" /etc/lightdm
  fi

  ok "Restore complete. Run: sudo apt-get update && sudo apt-get -f install"
}

###############################################################################
# Third-party sources handling (best-effort allowlist for common corp repos)
###############################################################################
file_contains_any() {
  local file="$1"; shift
  local pat=""
  for pat in "$@"; do
    if grep -qiE "$pat" "$file" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

is_allowlisted_thirdparty_source() {
  local file="$1"
  # Keep common enterprise repos & key services that often underpin corporate agents.
  # This is intentionally conservative to avoid breaking GlobalProtect/CrowdStrike/etc.
  file_contains_any "$file" \
    "crowdstrike" "falcon" \
    "paloaltonetworks" "globalprotect" \
    "zscaler" \
    "vmware" "broadcom" \
    "packages\.microsoft\.com" \
    "dl\.google\.com/linux" \
    "repo\.cloud\.google\.com" \
    "nvidia" \
    "docker\.com" \
    "apt\.releases\.hashicorp\.com" \
    "artifactory" "nexus" "jfrog" \
    "repo\." "packages\." "apt\."
}

disable_thirdparty_sources_system() {
  local backup_dir="$1"
  local disabled_dir="${backup_dir}/disabled-sources"
  mkdir -p "$disabled_dir"

  info "Disabling 3rd-party sources into: ${disabled_dir}"
  shopt -s nullglob

  local f=""
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ "$(basename "$f")" == "$(basename "$SOURCES_OUT")" ]] && continue

    if [[ "$KEEP_PPAS" == "yes" ]]; then
      continue
    fi

    # Allowlist heuristic: keep some corp repos
    if is_allowlisted_thirdparty_source "$f"; then
      warn "Keeping allowlisted third-party source: $f"
      continue
    fi

    mv -v "$f" "${disabled_dir}/" || true
  done

  shopt -u nullglob
  ok "Third-party sources handled."
}

###############################################################################
# Mint keyring: prefer linuxmint-keyring .deb (avoids keyservers)
###############################################################################
fetch_linuxmint_keyring_deb() {
  local out_deb="$1"
  local base="${MINT_MIRROR%/}/pool/main/l/linuxmint-keyring/"
  local index_html
  index_html="$(mktemp)"
  if ! curl -fsSL "$base" -o "$index_html"; then
    rm -f "$index_html"
    die "Unable to fetch linuxmint-keyring directory index from ${base}"
  fi

  # Extract candidates; pick newest by version sort
  local candidates
  candidates="$(grep -oE 'linuxmint-keyring_[0-9][0-9][0-9][0-9][^"]*_all\.deb' "$index_html" | sort -u || true)"
  rm -f "$index_html"

  local chosen=""
  if [[ -n "$candidates" ]]; then
    # sort -V to pick latest-looking version string
    chosen="$(printf '%s\n' $candidates | sort -V | tail -n 1)"
  fi

  # Fallback known good version if parsing fails
  if [[ -z "$chosen" ]]; then
    chosen="linuxmint-keyring_2022.06.21_all.deb"
    warn "Could not parse latest linuxmint-keyring from index; falling back to ${chosen}"
  fi

  local url="${base}${chosen}"
  info "Downloading linuxmint-keyring package: ${url}"
  curl -fsSL "$url" -o "$out_deb" || die "Failed to download ${url}"
}

install_mint_repo_keyring() {
  local keyring="$KEYRING_OUT"

  if [[ -f "$keyring" ]]; then
    if [[ "$RECREATE_KEYRING" == "yes" ]]; then
      info "Recreating existing keyring: ${keyring}"
      cp -a "$keyring" "${keyring}.bak.$(date +%s)" || true
      rm -f "$keyring"
    elif [[ "$OVERWRITE_KEYRING" == "yes" ]]; then
      info "Overwriting existing keyring: ${keyring}"
      cp -a "$keyring" "${keyring}.bak.$(date +%s)" || true
      rm -f "$keyring"
    else
      info "Keyring already exists: ${keyring} (use --overwrite-keyring or --recreate-keyring to replace)"
      return 0
    fi
  fi

  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts
  apt-get "${apt_opts[@]}" update
  apt-get "${apt_opts[@]}" install curl ca-certificates dpkg-dev gnupg

  local tmpdir; tmpdir="$(mktemp -d)"
  chmod 700 "$tmpdir"

  local deb="${tmpdir}/linuxmint-keyring.deb"
  fetch_linuxmint_keyring_deb "$deb"

  # Extract package, find key file(s)
  dpkg-deb -x "$deb" "$tmpdir/extract"

  local found_gpg=""
  found_gpg="$(find "$tmpdir/extract" -type f \( -name '*.gpg' -o -name '*.asc' \) | grep -i 'linuxmint' | head -n 1 || true)"
  [[ -n "$found_gpg" ]] || die "Could not locate a linuxmint key file inside linuxmint-keyring package."

  mkdir -p "$(dirname "$keyring")"
  rm -f "$keyring" || true

  if [[ "$found_gpg" == *.gpg ]]; then
    cp -a "$found_gpg" "$keyring"
  else
    # Convert .asc to binary .gpg keyring
    # Ensure output doesn't exist to avoid "dearmoring failed: File exists"
    rm -f "$keyring" || true
    gpg --batch --dearmor -o "$keyring" "$found_gpg"
  fi

  chmod 644 "$keyring"
  rm -rf "$tmpdir"
  ok "Mint repo keyring installed at ${keyring}"
}

###############################################################################
# Ubuntu mirror detection
###############################################################################
UBUNTU_ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
UBUNTU_SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

detect_ubuntu_mirrors() {
  # If system uses a custom mirror in sources, reuse it. Otherwise defaults above.
  local first=""
  first="$(grep -RhoE '^deb[[:space:]]+https?://[^[:space:]]+/ubuntu' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head -n 1 || true)"
  if [[ -n "$first" ]]; then
    local url
    url="$(echo "$first" | awk '{print $2}' | sed 's#/ubuntu$##')"
    UBUNTU_ARCHIVE_MIRROR="${url%/}/ubuntu"
    # security mirror stays default unless explicitly detected
  fi
  info "Ubuntu archive mirror:  ${UBUNTU_ARCHIVE_MIRROR}"
  info "Ubuntu security mirror: ${UBUNTU_SECURITY_MIRROR}"
}

###############################################################################
# Write sources + pinning
###############################################################################
write_mint_sources_system() {
  local list="$SOURCES_OUT"
  local keyring="$KEYRING_OUT"

  detect_ubuntu_mirrors

  info "Writing Mint+Ubuntu sources to ${list}"
  cat > "$list" <<EOF
# Do not edit this file manually.
# Generated by ${SCRIPT_NAME} on $(date -Is)
#
# Linux Mint repository:
deb [signed-by=${keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport

# Ubuntu base repositories:
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  # Comment out legacy /etc/apt/sources.list entries to reduce duplication
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^[[:space:]]*deb /# deb /' /etc/apt/sources.list || true
  fi

  ok "Sources written."
}

write_mint_pinning_system() {
  info "Writing APT pinning..."

  # Base pin: Mint origin low by default (Ubuntu remains base for overlaps)
  cat > "$PIN_BASE_OUT" <<'EOF'
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 100

# Prefer Ubuntu as the general default (keep base stable)
Package: *
Pin: release o=Ubuntu
Pin-Priority: 500
EOF

  # Desktop stack pin: force Mint for the desktop stack to avoid mixed-version crashes
  cat > "$PIN_STACK_OUT" <<'EOF'
# Strongly prefer Mint for desktop stack packages to avoid ABI/API mismatches
Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: cinnamon* nemo* muffin* cjs* libcjs0* gir1.2-cmenu* libcinnamon* xapp* xapps-common xapp-gtk3-module slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons* mint-artwork*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF

  # Preserve snap (prevent accidental removal)
  cat > "$SNAP_PREF_OUT" <<EOF
Package: snapd*
Pin: release o=Ubuntu
Pin-Priority: 1001
EOF

  ok "Pinning written."
}

###############################################################################
# APT simulation safety checks
###############################################################################
critical_packages_list() {
  local crit=(
    "sudo"
    "systemd"
    "systemd-sysv"
    "dbus"
    "network-manager"
    "openssh-server"
    "linux-image-generic"
    "linux-generic"
    "grub2-common"
  )
  if [[ "$PRESERVE_SNAP" == "yes" ]]; then
    crit+=("snapd")
  fi
  printf '%s\n' "${crit[@]}"
}

apt_simulate_install() {
  local sim_out="$1"
  shift
  local pkgs=("$@")

  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts

  # Print the simulation output to both stdout and file.
  # (The command caller may tee it as well; this is fine.)
  apt-get -s "${apt_opts[@]}" install "${pkgs[@]}" | tee "$sim_out" >/dev/null
}

apt_sim_parse_removals() {
  local sim_out="$1"

  # apt-get -s output shows lines like:
  #   Remv package [version]
  #   Remv package:amd64 [version]
  local removed_count
  removed_count="$(grep -E '^Remv[[:space:]]' "$sim_out" | wc -l | tr -d ' ')"
  echo "${removed_count:-0}"
}

apt_sim_list_removed_pkgs() {
  local sim_out="$1"
  grep -E '^Remv[[:space:]]' "$sim_out" | awk '{print $2}' | sed 's/:amd64$//' | sort -u || true
}

apt_sim_abort_if_unsafe() {
  local sim_out="$1"
  local removal_count
  removal_count="$(apt_sim_parse_removals "$sim_out")"
  info "APT simulation removals: ${removal_count} (threshold ${MAX_ALLOWED_REMOVALS})"

  if (( removal_count > MAX_ALLOWED_REMOVALS )); then
    err "APT wants to remove too many packages (${removal_count}). Aborting."
    err "Review: ${sim_out}"
    exit 100
  fi

  local removed; removed="$(apt_sim_list_removed_pkgs "$sim_out")"
  if [[ -n "$removed" ]]; then
    local crit; crit="$(critical_packages_list)"
    local p=""
    while IFS= read -r p; do
      if grep -qxF "$p" <<<"$crit"; then
        err "APT simulation wants to remove critical package: ${p}"
        err "Aborting. Review: ${sim_out}"
        exit 100
      fi
    done <<<"$removed"
  fi

  ok "Simulation safety checks passed."
}

###############################################################################
# Conflicting packages (Ubuntu flavors & known dpkg conflicts)
###############################################################################
purge_conflicting_flavors_best_effort() {
  [[ "$PURGE_CONFLICTING_FLAVORS" == "yes" ]] || return 0

  # Ubuntu Cinnamon flavor packages can conflict with Mint cinnamon stack.
  # We remove them if installed.
  local conflicts=(
    "ubuntucinnamon-desktop"
    "ubuntucinnamon-environment"
    "ubuntucinnamon-settings"
    "ubuntucinnamon-wallpapers"
    "ubuntucinnamon-*"
    "cinnamon-desktop-environment"
  )

  local installed_any="no"
  local c=""
  for c in "${conflicts[@]}"; do
    if dpkg -l 2>/dev/null | awk '{print $2}' | grep -qxE "${c//\*/.*}"; then
      installed_any="yes"
      break
    fi
  done
  [[ "$installed_any" == "yes" ]] || return 0

  warn "Purging potentially conflicting Ubuntu flavor packages (best-effort)..."
  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts
  # Use purge with globs; if nothing matches, apt ignores.
  apt-get "${apt_opts[@]}" purge ubuntucinnamon-desktop ubuntucinnamon-\* cinnamon-desktop-environment || true
  apt-get "${apt_opts[@]}" autoremove || true
  ok "Conflict purge attempt complete."
}

remove_software_properties_gtk_best_effort() {
  # Known conflict: mintupdate may try to overwrite an icon owned by software-properties-gtk on Ubuntu.
  # Safer approach: remove the Ubuntu GUI tool (does not remove add-apt-repository / software-properties-common).
  if dpkg -s software-properties-gtk >/dev/null 2>&1; then
    warn "Removing software-properties-gtk to avoid dpkg file overwrite conflicts with Mint tooling (best-effort)..."
    export DEBIAN_FRONTEND=noninteractive
    local apt_opts=(); apt_get_opts_common apt_opts
    apt-get "${apt_opts[@]}" remove software-properties-gtk || true
    ok "software-properties-gtk removal attempted."
  fi
}

###############################################################################
# Display manager / session defaults (per edition)
###############################################################################
session_name_for_edition() {
  case "$EDITION" in
    cinnamon) echo "cinnamon" ;;
    xfce) echo "xfce" ;;
    mate) echo "mate" ;;
    *) echo "cinnamon" ;;
  esac
}

ensure_x11_common_present() {
  # Fixes cases where /etc/X11/Xsession lacks helpers (e.g., has_option) due to missing x11-common.
  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts
  apt-get "${apt_opts[@]}" install --reinstall x11-common || true
}

configure_lightdm_and_session() {
  local sess; sess="$(session_name_for_edition)"

  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts

  info "Installing display manager components (LightDM + slick-greeter)..."
  apt-get "${apt_opts[@]}" install lightdm slick-greeter || die "Failed to install LightDM stack"

  ensure_x11_common_present

  info "Configuring LightDM defaults for session '${sess}'..."
  mkdir -p "$(dirname "$LIGHTDM_PREF_OUT")"
  cat > "$LIGHTDM_PREF_OUT" <<EOF
# Generated by ${SCRIPT_NAME} on $(date -Is)
[Seat:*]
greeter-session=slick-greeter
user-session=${sess}
EOF

  # Set default display manager non-interactively
  if have_cmd debconf-set-selections; then
    echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true
  fi
  if have_cmd dpkg-reconfigure; then
    dpkg-reconfigure -f noninteractive lightdm || true
  fi

  # Disable gdm3 if installed/enabled (common on Ubuntu GNOME)
  if systemctl is-enabled gdm3 >/dev/null 2>&1; then
    warn "Disabling gdm3 to prefer LightDM..."
    systemctl disable --now gdm3 || true
  fi

  systemctl enable --now lightdm || true

  ok "LightDM configured. Default session set to '${sess}'."
}

###############################################################################
# Timeshift snapshot (best-effort)
###############################################################################
timeshift_snapshot_best_effort() {
  if have_cmd timeshift; then
    info "Timeshift detected. Attempting pre-change snapshot (best-effort)..."
    timeshift --create --comments "pre ubuntu->mint $(date -Is)" --tags D || warn "Timeshift snapshot failed (may not be configured)."
  else
    warn "Timeshift not installed. Strongly recommended to snapshot/backup before converting."
  fi
}

###############################################################################
# Plan mode (dry-run using temporary APT root; does not touch /etc/apt)
###############################################################################
make_temp_apt_root() {
  local tmp; tmp="$(mktemp -d)"
  mkdir -p "$tmp/etc/apt/sources.list.d" "$tmp/etc/apt/preferences.d" "$tmp/usr/share/keyrings"
  mkdir -p "$tmp/var/lib/apt/lists/partial" "$tmp/var/cache/apt/archives/partial"
  echo "$tmp"
}

apt_cmd_with_root() {
  # Prints apt-get args to use a temp root (caller should use eval-safe arrays directly)
  local root="$1"
  echo "-o Dir::Etc=${root}/etc/apt -o Dir::Etc::sourcelist=${root}/etc/apt/sources.list -o Dir::Etc::sourceparts=${root}/etc/apt/sources.list.d -o Dir::Etc::preferencesparts=${root}/etc/apt/preferences.d -o Dir::State=${root}/var/lib/apt -o Dir::State::Lists=${root}/var/lib/apt/lists -o Dir::Cache=${root}/var/cache/apt -o Dir::Cache::archives=${root}/var/cache/apt/archives -o APT::Get::List-Cleanup=0"
}

plan_mode() {
  require_root
  setup_logging
  parse_args "$@"
  detect_os
  check_apt_locks

  info "Plan mode: creating temporary APT environment (no changes to /etc/apt)..."
  local root; root="$(make_temp_apt_root)"
  local plan_log="${LOG_DIR}/plan-$(date +%Y%m%d-%H%M%S).txt"

  # Temp keyring
  local tmp_keyring="${root}/usr/share/keyrings/linuxmint-repo.gpg"
  local old_keyring_out="$KEYRING_OUT"
  KEYRING_OUT="$tmp_keyring"
  install_mint_repo_keyring
  KEYRING_OUT="$old_keyring_out"

  # Temp sources
  local tmp_sources="${root}/etc/apt/sources.list.d/official-package-repositories.list"
  local tmp_pref_base="${root}/etc/apt/preferences.d/50-linuxmint-conversion.pref"
  local tmp_pref_stack="${root}/etc/apt/preferences.d/51-linuxmint-desktop-stack.pref"

  detect_ubuntu_mirrors

  cat > "$tmp_sources" <<EOF
deb [signed-by=${tmp_keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  # Pinning in temp root
  cat > "$tmp_pref_base" <<'EOF'
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 100

Package: *
Pin: release o=Ubuntu
Pin-Priority: 500
EOF

  cat > "$tmp_pref_stack" <<'EOF'
Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: cinnamon* nemo* muffin* cjs* libcjs0* gir1.2-cmenu* libcinnamon* xapp* xapps-common xapp-gtk3-module slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons* mint-artwork*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF

  # Run update + simulation inside temp root
  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts

  info "Plan: apt-get update (temp root)..."
  # shellcheck disable=SC2206
  local root_opts=($(apt_cmd_with_root "$root"))
  apt-get "${root_opts[@]}" "${apt_opts[@]}" update | tee "$plan_log" >/dev/null

  local meta_pkg="mint-meta-${EDITION}"
  local pkgs=( "$meta_pkg" mint-meta-core mintsystem mintupdate mintsources mint-meta-codecs )

  info "Plan: Simulation (temp root) of install: ${pkgs[*]}"
  apt-get "${root_opts[@]}" -s "${apt_opts[@]}" install "${pkgs[@]}" | tee -a "$plan_log" >/dev/null || true

  info "Plan written to: ${plan_log}"
  ok "Plan complete (no system APT changes made)."
  rm -rf "$root"
}

###############################################################################
# Convert
###############################################################################
convert_mode() {
  require_root
  setup_logging
  parse_args "$@"
  detect_os
  check_apt_locks
  convert_disclaimer_gate

  [[ "$AUTO_FIX" == "yes" ]] && apt_fix_basic

  timeshift_snapshot_best_effort

  BACKUP_DIR="$(backup_system_state)"
  info "Backup directory: ${BACKUP_DIR}"

  if [[ "$KEEP_PPAS" != "yes" ]]; then
    disable_thirdparty_sources_system "$BACKUP_DIR"
  else
    warn "--keep-ppas enabled; third-party sources remain active (higher risk)."
  fi

  # Ensure Mint keyring exists (handle overwrite/recreate rules)
  install_mint_repo_keyring

  # Write sources + pinning
  write_mint_sources_system
  write_mint_pinning_system

  # If requested, preserve snap strongly; also treat snapd as "must keep" in simulation checks
  if [[ "$PRESERVE_SNAP" == "yes" ]]; then
    ok "Snap preservation enabled."
  else
    warn "Snap preservation disabled."
  fi

  # Attempt to reduce known conflicts before installing Mint stack
  purge_conflicting_flavors_best_effort
  remove_software_properties_gtk_best_effort

  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(); apt_get_opts_common apt_opts

  info "APT update..."
  apt-get "${apt_opts[@]}" update

  # Simulation first
  local sim_out="${BACKUP_DIR}/apt-simulate-install.txt"
  local meta_pkg="mint-meta-${EDITION}"
  local pkgs=( "$meta_pkg" mint-meta-core mintsystem mintupdate mintsources mint-meta-codecs )

  info "Simulation (safety check) of install: ${pkgs[*]}"
  apt_simulate_install "$sim_out" "${pkgs[@]}" || true
  apt_sim_abort_if_unsafe "$sim_out"

  # Install Mint stack (with force-overwrite options available if needed)
  info "Installing Mint stack..."
  local apt_force=(); apt_get_opts_force_overwrite apt_force

  # First try normal install; if dpkg conflict hits, retry with force-overwrite.
  if ! apt-get "${apt_opts[@]}" install "${pkgs[@]}"; then
    warn "Initial install failed; retrying with dpkg --force-overwrite (best-effort)..."
    apt-get "${apt_force[@]}" install "${pkgs[@]}" || die "Mint stack install failed even with force-overwrite."
  fi

  ok "Mint stack installed."

  # Configure display manager + defaults per edition
  configure_lightdm_and_session

  # Post-conversion validation
  post_convert_validate

  ok "Conversion complete."
  echo
  echo "${c_bold}Recommended next step:${c_reset} reboot and select '${EDITION}' session in LightDM (if prompted)."
}

###############################################################################
# Post-conversion validation
###############################################################################
write_validation_line() {
  local out="$1"; shift
  echo "[$(date -Is)] $*" >> "$out"
}

post_convert_validate() {
  local out="${BACKUP_DIR}/post-convert-validation.txt"
  : > "$out" || true

  info "Post-conversion validation writing to: ${out}"

  write_validation_line "$out" "Ubuntu base: ${UBUNTU_BASE}"
  write_validation_line "$out" "Mint target: ${TARGET_MINT}"
  write_validation_line "$out" "Edition: ${EDITION}"
  write_validation_line "$out" "Mint mirror: ${MINT_MIRROR}"
  write_validation_line "$out" "Keyring: ${KEYRING_OUT}"

  # Key packages
  local check_pkgs=( "mintsystem" "mintupdate" "mintsources" "lightdm" "slick-greeter" )
  if [[ "$EDITION" == "cinnamon" ]]; then
    check_pkgs+=( "cinnamon-session" "muffin" "nemo" "cjs" )
  elif [[ "$EDITION" == "xfce" ]]; then
    check_pkgs+=( "xfce4-session" "xfwm4" )
  elif [[ "$EDITION" == "mate" ]]; then
    check_pkgs+=( "mate-session-manager" )
  fi

  local p=""
  for p in "${check_pkgs[@]}"; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      write_validation_line "$out" "OK pkg: $p"
    else
      write_validation_line "$out" "MISSING pkg: $p"
    fi
  done

  # APT sanity
  if apt-get -s check >/dev/null 2>&1; then
    write_validation_line "$out" "APT check: OK"
  else
    write_validation_line "$out" "APT check: FAILED"
  fi

  # LightDM enabled?
  if systemctl is-enabled lightdm >/dev/null 2>&1; then
    write_validation_line "$out" "LightDM: enabled"
  else
    write_validation_line "$out" "LightDM: NOT enabled"
  fi

  # Xsession helper presence (has_option errors usually indicate x11-common issues)
  if [[ -f /etc/X11/Xsession ]]; then
    write_validation_line "$out" "/etc/X11/Xsession: present"
  else
    write_validation_line "$out" "/etc/X11/Xsession: MISSING"
  fi

  # Note: We do not attempt to validate corporate tooling, but record common services if present
  local maybe_services=( "falcon-sensor" "crowdstrike-falcon-sensor" "gpd" "GlobalProtect" "globalprotect" )
  local s=""
  for s in "${maybe_services[@]}"; do
    if systemctl list-units --type=service --all | grep -qi "$s"; then
      write_validation_line "$out" "NOTE service match: ${s}"
    fi
  done

  ok "Post-conversion validation complete."
}

###############################################################################
# Rollback
###############################################################################
rollback_mode() {
  require_root
  setup_logging

  local backup_dir="${1:-}"
  [[ -n "$backup_dir" ]] || die "Usage: ${SCRIPT_NAME} rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS"
  restore_backup "$backup_dir"
}

###############################################################################
# Main
###############################################################################
main() {
  case "$SUBCMD" in
    doctor)
      require_root
      setup_logging
      parse_args "$@"
      detect_os
      check_apt_locks
      [[ "$AUTO_FIX" == "yes" ]] && apt_fix_basic
      doctor_report
      ;;
    plan)
      plan_mode "$@"
      ;;
    convert)
      convert_mode "$@"
      ;;
    rollback)
      rollback_mode "$@"
      ;;
    ""|help|-h|--help)
      usage
      ;;
    *)
      usage
      die "Unknown subcommand: ${SUBCMD}"
      ;;
  esac
}

main "$@"
