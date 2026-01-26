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
# Version / globals
###############################################################################
SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="4.4"

LOG_DIR="/var/log/ubuntu-to-mint"
DEFAULT_MINT_MIRROR="http://packages.linuxmint.com"
KEYRING_OUT="/usr/share/keyrings/linuxmint-repo.gpg"
SOURCES_OUT="/etc/apt/sources.list.d/official-package-repositories.list"
PIN_OUT="/etc/apt/preferences.d/50-linuxmint-conversion.pref"
PIN_STACK_OUT="/etc/apt/preferences.d/51-linuxmint-desktop-stack.pref"

# Safety thresholds
MAX_ALLOWED_REMOVALS_DEFAULT=40

# Runtime state
SUBCMD="${1:-}"
shift || true

UBUNTU_BASE=""
DEFAULT_MINT=""
ALLOWED_TARGETS=""
TARGET_MINT=""
EDITION="cinnamon"
MINT_MIRROR="$DEFAULT_MINT_MIRROR"
KEEP_PPAS="no"
PRESERVE_SNAP="yes"
WITH_RECOMMENDS="no"
ASSUME_YES="no"
RISK_ACK_FLAG="no"
PREFER_WAYLAND="no"   # With LightDM we will force X11 anyway.
OVERWRITE_KEYRING="no" # overwrite keyring file if exists
RECREATE_KEYRING="no"  # delete+recreate keyring if exists (back it up)
AUTO_FIX="yes"         # attempt basic dpkg/apt repair pre-flight
PURGE_CONFLICTING_FLAVORS="yes"  # purge ubuntucinnamon / flavor meta packages that break Mint DE
MAX_ALLOWED_REMOVALS="$MAX_ALLOWED_REMOVALS_DEFAULT"

BACKUP_DIR=""
ON_ERROR_BACKUP_HINT=""

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
LOG_FILE=""
setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/ubuntu-to-mint-$(date +%Y%m%d-%H%M%S).log"
  # tee while preserving stderr
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
  --yes                            Skip most interactive prompts (convert still requires disclaimer + --i-accept-the-risk)
  --max-removals N                 Abort if APT simulation removes more than N packages (default: ${MAX_ALLOWED_REMOVALS_DEFAULT})

  --overwrite-keyring              If ${KEYRING_OUT} exists, overwrite it
  --recreate-keyring               Backup+delete ${KEYRING_OUT} then recreate it

  --no-auto-fix                    Do not attempt dpkg/apt repair pre-flight
  --no-purge-flavor                Do not purge conflicting Ubuntu-flavor packages (ubuntucinnamon*, etc.)

Notes:
  * "convert" will force LightDM + X11 session by default (Mint-style). Wayland is not used by LightDM.
EOF
}

###############################################################################
# Argument parsing
###############################################################################
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --edition)
        EDITION="${2:-}"; shift 2 ;;
      --target)
        TARGET_MINT="${2:-}"; shift 2 ;;
      --mint-mirror)
        MINT_MIRROR="${2:-}"; shift 2 ;;
      --keep-ppas)
        KEEP_PPAS="yes"; shift ;;
      --preserve-snap)
        PRESERVE_SNAP="yes"; shift ;;
      --no-preserve-snap)
        PRESERVE_SNAP="no"; shift ;;
      --with-recommends)
        WITH_RECOMMENDS="yes"; shift ;;
      --yes)
        ASSUME_YES="yes"; shift ;;
      --i-accept-the-risk)
        RISK_ACK_FLAG="yes"; shift ;;
      --overwrite-keyring)
        OVERWRITE_KEYRING="yes"; shift ;;
      --recreate-keyring)
        RECREATE_KEYRING="yes"; shift ;;
      --no-auto-fix)
        AUTO_FIX="no"; shift ;;
      --no-purge-flavor)
        PURGE_CONFLICTING_FLAVORS="no"; shift ;;
      --max-removals)
        MAX_ALLOWED_REMOVALS="${2:-}"; shift 2 ;;
      -h|--help|help)
        usage; exit 0 ;;
      *)
        die "Unknown argument: $1 (use --help)" ;;
    esac
  done

  case "$EDITION" in
    cinnamon|mate|xfce) : ;;
    *) die "--edition must be cinnamon|mate|xfce" ;;
  esac

  [[ "$MAX_ALLOWED_REMOVALS" =~ ^[0-9]+$ ]] || die "--max-removals must be an integer"
}

###############################################################################
# System checks
###############################################################################
require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (use sudo)."
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
      ALLOWED_TARGETS="zena zara xia wilma"
      ;;
    jammy)
      UBUNTU_BASE="jammy"
      DEFAULT_MINT="virginia"
      ALLOWED_TARGETS="virginia victoria vera vanessa"
      ;;
    *)
      die "Unsupported Ubuntu codename '${codename}'. Supported: noble (24.04), jammy (22.04)."
      ;;
  esac

  if [[ -z "$TARGET_MINT" ]]; then
    TARGET_MINT="$DEFAULT_MINT"
  fi

  local ok_target="no"
  for t in $ALLOWED_TARGETS; do
    [[ "$TARGET_MINT" == "$t" ]] && ok_target="yes"
  done
  [[ "$ok_target" == "yes" ]] || die "--target '${TARGET_MINT}' not allowed for Ubuntu '${UBUNTU_BASE}'. Allowed: ${ALLOWED_TARGETS}"

  info "Ubuntu base: ${UBUNTU_BASE} | Target Mint codename: ${TARGET_MINT} | Edition: ${EDITION}"
}

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

  local holds
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
  local dir="/root/ubuntu-to-mint-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$dir"
  info "Creating backup at: ${dir}"

  mkdir -p "${dir}/etc"
  cp -a /etc/apt "${dir}/etc/" || true
  cp -a /etc/os-release /etc/lsb-release 2>/dev/null "${dir}/etc/" || true
  cp -a /etc/fstab /etc/hostname /etc/hosts 2>/dev/null "${dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${dir}/apt-manual.txt" || true
  apt-mark showhold > "${dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${dir}/enabled-services.txt" || true

  if have_cmd snap; then snap list > "${dir}/snap-list.txt" || true; fi
  if have_cmd flatpak; then flatpak list > "${dir}/flatpak-list.txt" || true; fi

  ok "Backup complete."
  echo "$dir"
}

rollback_from_backup() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || die "rollback requires a backup directory path."
  [[ -d "$dir" ]] || die "Backup directory not found: $dir"
  [[ -d "${dir}/etc/apt" ]] || die "Backup missing ${dir}/etc/apt"

  info "Restoring /etc/apt from backup: ${dir}"
  rm -rf /etc/apt
  cp -a "${dir}/etc/apt" /etc/apt
  ok "APT config restored."

  info "Running apt-get update + fix-broken (best-effort)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get -y update || true
  apt-get -y -f install || true
  ok "Rollback complete. Reboot recommended."
}

timeshift_snapshot_best_effort() {
  if have_cmd timeshift; then
    info "Timeshift detected. Attempting pre-change snapshot (best-effort)..."
    timeshift --create --comments "pre ubuntu->mint ${EDITION} $(date -Is)" --tags D \
      || warn "Timeshift snapshot failed (may not be configured)."
  else
    warn "Timeshift not installed. Strongly recommended to snapshot/backup before converting."
  fi
}

###############################################################################
# Third-party sources handling
###############################################################################
is_enterprise_allowlisted_source() {
  # Avoid disabling common corporate agents repos
  # (CrowdStrike, Palo Alto GlobalProtect, etc.)
  local f="$1"
  grep -Eqi '(crowdstrike|falcon|paloaltonetworks|globalprotect|pan-gp|pan-globalprotect|zscaler|netskope|sentinelone)' "$f" 2>/dev/null
}

disable_thirdparty_sources_system() {
  local backup_dir="$1"
  local disabled_dir="${backup_dir}/disabled-sources"
  mkdir -p "$disabled_dir"

  info "Disabling 3rd-party sources into: ${disabled_dir}"
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ "$(basename "$f")" == "$(basename "$SOURCES_OUT")" ]] && continue
    if [[ "$KEEP_PPAS" == "yes" ]]; then
      continue
    fi
    if is_enterprise_allowlisted_source "$f"; then
      warn "Keeping allowlisted corporate source: $f"
      continue
    fi
    mv -v "$f" "${disabled_dir}/" || true
  done
  shopt -u nullglob

  ok "Third-party sources disabled (restorable via rollback)."
}

###############################################################################
# Mint keyring retrieval (NO keyserver dependency by default)
###############################################################################
ensure_deps_for_keyring() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get -y update
  apt-get -y install ca-certificates curl gnupg dirmngr dpkg-dev >/dev/null
}

keyring_from_installed_package() {
  # If linuxmint-keyring is installed, copy the keyring file(s) from it.
  if ! dpkg -s linuxmint-keyring >/dev/null 2>&1; then
    return 1
  fi

  local files
  files="$(dpkg -L linuxmint-keyring 2>/dev/null | grep -E '/usr/share/keyrings/.*\.(gpg|asc)$' || true)"
  [[ -n "$files" ]] || return 1

  local src
  src="$(echo "$files" | grep -E '\.gpg$' | head -n 1 || true)"
  if [[ -z "$src" ]]; then
    src="$(echo "$files" | head -n 1)"
  fi
  [[ -r "$src" ]] || return 1

  echo "$src"
  return 0
}

fetch_latest_linuxmint_keyring_deb() {
  local pool_base="${MINT_MIRROR%/}/pool/main/l/linuxmint-keyring/"
  local tmpdir="$1"
  mkdir -p "$tmpdir"

  # Try HTTPS first, then HTTP.
  local index=""
  if index="$(curl -fsSL "https://$(echo "$pool_base" | sed 's|^http://||')" 2>/dev/null)"; then
    :
  elif index="$(curl -fsSL "$pool_base" 2>/dev/null)"; then
    :
  else
    return 1
  fi

  # Extract deb names
  local debs
  debs="$(echo "$index" | grep -oE 'linuxmint-keyring_[0-9A-Za-z.+:~_-]+_all\.deb' | sort -Vu | uniq || true)"
  [[ -n "$debs" ]] || return 1

  local deb
  deb="$(echo "$debs" | tail -n 1)"
  local url="${pool_base}${deb}"

  info "Downloading linuxmint-keyring package: ${deb}"
  if ! curl -fsSL "$url" -o "${tmpdir}/${deb}"; then
    # attempt https variant if pool_base was http
    local https_url="https://$(echo "$url" | sed 's|^http://||')"
    curl -fsSL "$https_url" -o "${tmpdir}/${deb}" || return 1
  fi

  echo "${tmpdir}/${deb}"
  return 0
}

extract_keyring_from_deb_to() {
  local deb_path="$1"
  local out_keyring="$2"

  [[ -r "$deb_path" ]] || die "Keyring deb not readable: $deb_path"
  [[ -n "$out_keyring" ]] || die "extract_keyring_from_deb_to requires output path"

  local tmpdir
  tmpdir="$(mktemp -d)"
  chmod 700 "$tmpdir"

  dpkg-deb -x "$deb_path" "$tmpdir"

  local candidate=""
  if [[ -d "$tmpdir/usr/share/keyrings" ]]; then
    candidate="$(find "$tmpdir/usr/share/keyrings" -maxdepth 1 -type f -name '*.gpg' | head -n 1 || true)"
  fi

  if [[ -z "$candidate" ]]; then
    # maybe shipped as .asc
    candidate="$(find "$tmpdir/usr/share/keyrings" -maxdepth 1 -type f -name '*.asc' | head -n 1 || true)"
  fi

  [[ -n "$candidate" ]] || die "Could not find Mint keyring inside linuxmint-keyring deb."

  mkdir -p "$(dirname "$out_keyring")"

  local tmp_out
  tmp_out="$(mktemp)"
  rm -f "$tmp_out" 2>/dev/null || true

  if [[ "$candidate" == *.gpg ]]; then
    cp -f "$candidate" "$tmp_out"
  else
    # .asc -> dearmor
    grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$candidate" \
      || die "Extracted key file does not look like an armored PGP public key."
    gpg --batch --dearmor -o "$tmp_out" "$candidate"
  fi

  chmod 644 "$tmp_out"
  mv -f "$tmp_out" "$out_keyring"
  chmod 644 "$out_keyring"

  rm -rf "$tmpdir"
}

mint_repo_key_write_to() {
  local out_keyring="$1"
  [[ -n "$out_keyring" ]] || die "mint_repo_key_write_to requires an output path"

  ensure_deps_for_keyring

  # Handle existing file behavior
  if [[ -e "$out_keyring" ]]; then
    if [[ "$RECREATE_KEYRING" == "yes" ]]; then
      local bak="${out_keyring}.$(date +%Y%m%d-%H%M%S).bak"
      warn "Recreating keyring: backing up existing to ${bak}"
      cp -a "$out_keyring" "$bak" || true
      rm -f "$out_keyring"
    elif [[ "$OVERWRITE_KEYRING" == "yes" ]]; then
      warn "Overwriting existing keyring at ${out_keyring}"
      :
    else
      # Validate it looks like a keyring; if yes, keep it.
      if gpg --batch --quiet --show-keys "$out_keyring" >/dev/null 2>&1; then
        ok "Existing Mint keyring looks valid; keeping ${out_keyring} (use --overwrite-keyring or --recreate-keyring to replace)."
        return 0
      fi
      die "Existing keyring at ${out_keyring} is not readable by gpg. Use --recreate-keyring to rebuild it."
    fi
  fi

  # Preferred: use linuxmint-keyring (installed) OR download its .deb and extract keyring.
  local src=""
  if src="$(keyring_from_installed_package 2>/dev/null)"; then
    info "Using keyring from installed linuxmint-keyring: ${src}"
    mkdir -p "$(dirname "$out_keyring")"
    cp -f "$src" "$out_keyring"
    chmod 644 "$out_keyring"
    ok "Key installed."
    return 0
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  chmod 700 "$tmpdir"

  local deb_path=""
  if deb_path="$(fetch_latest_linuxmint_keyring_deb "$tmpdir")"; then
    extract_keyring_from_deb_to "$deb_path" "$out_keyring"
    rm -rf "$tmpdir"
    ok "Key installed."
    return 0
  fi

  rm -rf "$tmpdir"
  die "Unable to obtain Mint keyring package from ${MINT_MIRROR}. Check proxy/firewall connectivity."
}

mint_repo_key_install_system() {
  info "Installing Linux Mint repo signing key into ${KEYRING_OUT}"
  mint_repo_key_write_to "$KEYRING_OUT"
}

###############################################################################
# Sources + pinning
###############################################################################
detect_ubuntu_mirrors() {
  # Keep it simple and stable; prefer existing mirrors if they look sane.
  UBUNTU_ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
  UBUNTU_SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

  # If system already uses a mirror, re-use it.
  local any
  any="$(grep -RhoE '^deb\s+http[^ ]+\s+' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head -n 1 || true)"
  if [[ -n "$any" ]]; then
    local m
    m="$(echo "$any" | awk '{print $2}')"
    if [[ "$m" == http*ubuntu.com/ubuntu* || "$m" == http* ]]; then
      UBUNTU_ARCHIVE_MIRROR="$m"
    fi
  fi
  info "Ubuntu archive mirror:  ${UBUNTU_ARCHIVE_MIRROR}"
  info "Ubuntu security mirror: ${UBUNTU_SECURITY_MIRROR}"
}

write_mint_sources_system() {
  detect_ubuntu_mirrors
  info "Writing Mint+Ubuntu sources to ${SOURCES_OUT}"

  mkdir -p "$(dirname "$SOURCES_OUT")"
  cat > "$SOURCES_OUT" <<EOF
# Do not edit this file manually.
# Generated by ${SCRIPT_NAME} on $(date -Is)
#
# Linux Mint repository:
deb [signed-by=${KEYRING_OUT}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport

# Ubuntu base repositories:
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  # Comment out classic /etc/apt/sources.list (avoid duplicates)
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^[[:space:]]*deb /# deb /' /etc/apt/sources.list || true
  fi

  ok "Sources written."
}

write_mint_pinning_system() {
  info "Writing conservative APT pinning to ${PIN_OUT}"
  cat > "$PIN_OUT" <<'EOF'
# Keep Ubuntu as the default source for overlapping packages.
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 100

# Prefer Mint tooling / meta packages.
Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome* mintinstall*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700
EOF
  ok "Base pinning written."

  info "Writing high-priority desktop stack pinning to ${PIN_STACK_OUT}"
  cat > "$PIN_STACK_OUT" <<'EOF'
# Desktop stacks MUST come from Mint repo to avoid Ubuntu/Mint version skew.
# (This prevents the "not installable" / mixed-version dependency issues.)
Package: cinnamon* nemo* muffin* cjs* libcjs* libmuffin* libnemo-extension* nemo-* xapp* xapps-* slick-greeter* lightdm* mint-themes* mint-y-icons* mint-x-icons* pix* xviewer* cinnamon-settings-daemon* cinnamon-control-center* cinnamon-session* cinnamon-desktop-data* cinnamon-l10n* libcinnamon* gir1.2-cmenu-3.0 libcinnamon-menu-3-0*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF
  ok "Desktop stack pinning written."
}

remove_nosnap_pref_if_needed() {
  if [[ "$PRESERVE_SNAP" == "yes" ]] && [[ -f /etc/apt/preferences.d/nosnap.pref ]]; then
    warn "Mint 'nosnap' preference detected at /etc/apt/preferences.d/nosnap.pref. Removing to preserve snap functionality."
    rm -f /etc/apt/preferences.d/nosnap.pref || true
  fi
}

###############################################################################
# Packages / simulation / install
###############################################################################
edition_meta_pkg() {
  case "$EDITION" in
    cinnamon) echo "mint-meta-cinnamon" ;;
    mate)     echo "mint-meta-mate" ;;
    xfce)     echo "mint-meta-xfce" ;;
  esac
}

edition_session_name() {
  case "$EDITION" in
    cinnamon) echo "cinnamon" ;;
    mate)     echo "mate" ;;
    xfce)     echo "xfce" ;;
  esac
}

required_packages_for_convert() {
  local meta
  meta="$(edition_meta_pkg)"
  cat <<EOF
${meta}
mint-meta-core
mint-meta-codecs
mintsystem
mintupdate
mintsources
mintdrivers
mintreport
lightdm
slick-greeter
dbus-x11
x11-common
xserver-xorg-core
xserver-xorg-legacy
EOF
}

apt_get_opts_common() {
  local opts=()
  opts+=("-y")
  opts+=("-o" "Dpkg::Use-Pty=0")
  opts+=("-o" "APT::Color=1")
  opts+=("-o" "Acquire::Retries=3")
  if [[ "$WITH_RECOMMENDS" == "no" ]]; then
    opts+=("--no-install-recommends")
  fi
  printf '%q ' "${opts[@]}"
}

apt_simulate_install() {
  local pkgs=("$@")
  export DEBIAN_FRONTEND=noninteractive

  info "APT simulation (safety check) of install:"
  printf '  %s\n' "${pkgs[@]}"

  local sim_out="${LOG_DIR}/plan-$(date +%Y%m%d-%H%M%S).txt"
  mkdir -p "$LOG_DIR"

  # Capture simulation output
  apt-get -s $(apt_get_opts_common) install "${pkgs[@]}" | tee "$sim_out" >/dev/null

  # Check removals count
  local removals
  removals="$(grep -E '^[[:space:]]*Remv[[:space:]]' "$sim_out" | wc -l | awk '{print $1}')"
  info "Simulation removals detected: ${removals} (max allowed: ${MAX_ALLOWED_REMOVALS})"
  if [[ "$removals" -gt "$MAX_ALLOWED_REMOVALS" ]]; then
    die "APT simulation wants to remove too many packages (${removals}). Aborting. Review: ${sim_out}"
  fi

  # Critical packages must never be removed
  local critical=(sudo systemd systemd-sysv network-manager linux-image-generic)
  for c in "${critical[@]}"; do
    if grep -E "^[[:space:]]*Remv[[:space:]]+${c}([[:space:]]|:)" "$sim_out" >/dev/null; then
      die "APT simulation wants to remove critical package '${c}'. Aborting. Review: ${sim_out}"
    fi
  done

  ok "Simulation looks within safety thresholds. Review log: ${sim_out}"
}

apt_install_mint_stack() {
  export DEBIAN_FRONTEND=noninteractive

  # Known dpkg overwrite conflict: mintupdate vs software-properties-gtk icon.
  # We force overwrite ONLY during the conversion install to avoid halting.
  local dpkg_force_overwrite=(
    "-o" "Dpkg::Options::=--force-overwrite"
    "-o" "Dpkg::Options::=--force-confnew"
  )

  local opts=()
  # shellcheck disable=SC2207
  opts+=($(apt_get_opts_common))
  info "Installing Mint stack (with dpkg overwrite guard for known file conflicts)..."

  apt-get "${opts[@]}" install "${dpkg_force_overwrite[@]}" "$@"
}

###############################################################################
# Display manager + session defaults
###############################################################################
disable_conflicting_lightdm_overrides() {
  local desired_session
  desired_session="$(edition_session_name)"

  if [[ -d /etc/lightdm/lightdm.conf.d ]]; then
    shopt -s nullglob
    for f in /etc/lightdm/lightdm.conf.d/*.conf; do
      # Keep our final file
      [[ "$(basename "$f")" == "99-ubuntu2mint.conf" ]] && continue

      # If a file forces a different user-session, disable it.
      if grep -Eq '^[[:space:]]*user-session=' "$f"; then
        local sess
        sess="$(grep -E '^[[:space:]]*user-session=' "$f" | tail -n1 | cut -d= -f2- | tr -d '[:space:]' || true)"
        if [[ -n "$sess" && "$sess" != "$desired_session" ]]; then
          warn "Disabling conflicting LightDM override (forces user-session=${sess}): ${f}"
          mv -f "$f" "${f}.u2m-disabled" || true
        fi
      fi
    done
    shopt -u nullglob
  fi
}

ensure_xsession_desktop_exists() {
  local sess
  sess="$(edition_session_name)"
  case "$sess" in
    cinnamon)
      if [[ ! -f /usr/share/xsessions/cinnamon.desktop ]]; then
        warn "Missing /usr/share/xsessions/cinnamon.desktop; creating a minimal session file."
        cat > /usr/share/xsessions/cinnamon.desktop <<'EOF'
[Desktop Entry]
Name=Cinnamon
Comment=This session logs you into Cinnamon
Exec=cinnamon-session-cinnamon
TryExec=cinnamon-session-cinnamon
Type=Application
DesktopNames=X-Cinnamon
EOF
      fi
      ;;
    mate)
      # mate.desktop typically provided; we won't fabricate unless missing
      if ! ls /usr/share/xsessions/*.desktop 2>/dev/null | grep -qi mate; then
        warn "MATE session desktop file not found under /usr/share/xsessions. Ensure mate-session is installed."
      fi
      ;;
    xfce)
      # xfce.desktop is typical
      if ! ls /usr/share/xsessions/*.desktop 2>/dev/null | grep -qi xfce; then
        warn "XFCE session desktop file not found under /usr/share/xsessions. Ensure xfce4-session is installed."
      fi
      ;;
  esac
}

set_display_manager_and_session_defaults() {
  local sess
  sess="$(edition_session_name)"

  info "Staging defaults: DM=lightdm, greeter=slick-greeter, session=${sess}"
  export DEBIAN_FRONTEND=noninteractive

  # Force LightDM as default display manager
  if have_cmd debconf-set-selections; then
    echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true
  fi

  # Ensure lightdm + slick-greeter are present (already in stack)
  apt-get -y install lightdm slick-greeter || true

  mkdir -p /etc/lightdm/lightdm.conf.d

  disable_conflicting_lightdm_overrides

  cat > /etc/lightdm/lightdm.conf.d/99-ubuntu2mint.conf <<EOF
# Generated by ${SCRIPT_NAME} on $(date -Is)
[Seat:*]
greeter-session=slick-greeter
user-session=${sess}
EOF

  ensure_xsession_desktop_exists

  # LightDM implies X11; make sure we don't end up attempting Wayland sessions.
  # (No explicit Wayland config is needed, but we also ensure x11-common is sane.)
  apt-get -y install x11-common dbus-x11 || true

  systemctl enable lightdm >/dev/null 2>&1 || true

  ok "Defaults staged: lightdm + ${sess}"
}

###############################################################################
# Cinnamon runtime sanity fixes (prevents login loop causes we observed)
###############################################################################
purge_conflicting_ubuntu_flavor_packages() {
  [[ "$PURGE_CONFLICTING_FLAVORS" == "yes" ]] || return 0

  export DEBIAN_FRONTEND=noninteractive
  local to_purge=()

  # ubuntucinnamon-environment (and friends) has been observed to inject gschema overrides
  # that don't match Mint Cinnamon, leading to crashes/login loops.
  if dpkg -l | awk '{print $2}' | grep -q '^ubuntucinnamon-'; then
    to_purge+=( $(dpkg -l | awk '{print $2}' | grep '^ubuntucinnamon-' || true) )
  fi

  # Remove ubuntu desktop metapackages only if present and edition is cinnamon,
  # since they can pull GNOME sessions and change defaults.
  if [[ "$EDITION" == "cinnamon" ]]; then
    for p in ubuntu-desktop gdm3; do
      if dpkg -s "$p" >/dev/null 2>&1; then
        warn "Detected package '${p}' which may keep GNOME as the default. It will NOT be purged automatically."
      fi
    done
  fi

  if [[ "${#to_purge[@]}" -gt 0 ]]; then
    warn "Purging conflicting Ubuntu flavor packages: ${to_purge[*]}"
    apt-get -y purge "${to_purge[@]}" || true
    apt-get -y autoremove || true
    ok "Conflicting flavor packages purged (best-effort)."
  fi
}

fix_cinnamon_symbol_rr_best_effort() {
  # If csd-* binaries exist, verify they can run (prevents LightDM login loop).
  # We observed: csd-power/csd-color undefined symbol gnome_rr_screen_new_async
  # Most often resolved by ensuring gnome-desktop / gnome-rr runtime libs are present and not partially removed.
  export DEBIAN_FRONTEND=noninteractive

  local any="no"
  [[ -x /usr/bin/csd-power ]] && any="yes"
  [[ -x /usr/bin/csd-color ]] && any="yes"
  [[ "$any" == "yes" ]] || return 0

  info "Validating cinnamon-settings-daemon helpers (csd-power/csd-color) best-effort..."

  local broken="no"
  if /usr/bin/csd-power --help >/dev/null 2>&1; then
    :
  else
    broken="yes"
  fi
  if [[ -x /usr/bin/csd-color ]] && ! /usr/bin/csd-color --help >/dev/null 2>&1; then
    broken="yes"
  fi

  if [[ "$broken" == "no" ]]; then
    ok "csd-power/csd-color appear runnable."
    return 0
  fi

  warn "csd-* helpers appear broken; attempting library remediation (best-effort)."

  # Ensure core Xsession bits exist (has_option errors typically indicate a broken x11-common installation)
  apt-get -y install --reinstall x11-common || true

  # Ensure GNOME desktop compatibility libs exist (Noble provides t64 packages)
  apt-get -y install --reinstall libgnome-desktop-3-20t64 libgnome-desktop-3-common || true

  # libgnome-rr-4 is a distinct runtime in Noble; install if available
  if apt-cache show libgnome-rr-4-2t64 >/dev/null 2>&1; then
    apt-get -y install --reinstall libgnome-rr-4-2t64 || true
  fi

  # Reinstall cinnamon-settings-daemon from Mint repo (pinning should prefer Mint)
  if dpkg -s cinnamon-settings-daemon >/dev/null 2>&1; then
    apt-get -y install --reinstall cinnamon-settings-daemon || true
  fi

  # Re-check
  if /usr/bin/csd-power --help >/dev/null 2>&1; then
    ok "csd-power is runnable after remediation."
  else
    warn "csd-power still appears broken. Cinnamon may login-loop. Check: ldd /usr/bin/csd-power; journalctl -b _UID=\$UID"
  fi
}

###############################################################################
# Disclaimer gate (convert only)
###############################################################################
convert_disclaimer_gate() {
  [[ "$SUBCMD" == "convert" ]] || return 0

  # Force explicit flag + interactive confirmation (even with --yes).
  [[ "$RISK_ACK_FLAG" == "yes" ]] || die "convert requires --i-accept-the-risk"

  echo
  echo "${c_red}${c_bold}======================================================================${c_reset}"
  echo "${c_red}${c_bold}   UNSUPPORTED MIGRATION METHOD — PROBABLY A REALLY DUMB IDEA${c_reset}"
  echo "${c_red}${c_bold}======================================================================${c_reset}"
  echo "${c_red}${c_bold}This script attempts to graft Linux Mint repositories/packages onto Ubuntu.${c_reset}"
  echo "${c_red}${c_bold}It is NOT supported by Linux Mint, Canonical, your IT department, or your employer.${c_reset}"
  echo "${c_red}${c_bold}It can break APT, boot/login, device management, VPN/EDR, and leave the system unrecoverable.${c_reset}"
  echo "${c_red}${c_bold}${c_reset}"
  echo "${c_red}${c_bold}Recommended approach: do a CLEAN Linux Mint install and restore your data/apps from backup.${c_reset}"
  echo "${c_red}${c_bold}If this is a corporate-managed device: STOP and get approval first.${c_reset}"
  echo "${c_red}${c_bold}======================================================================${c_reset}"
  echo

  echo "To continue anyway, type exactly:"
  echo "  I UNDERSTAND THIS IS UNSUPPORTED"
  echo "Anything else will abort."
  echo

  local answer=""
  read -r -p "> " answer
  [[ "$answer" == "I UNDERSTAND THIS IS UNSUPPORTED" ]] || die "Disclaimer not acknowledged. Aborting."
  ok "Disclaimer acknowledged."
}

###############################################################################
# Plan mode (safe simulation using TEMP sources + temp keyring)
###############################################################################
plan_mode() {
  require_root
  detect_os
  check_apt_locks

  if [[ "$AUTO_FIX" == "yes" ]]; then
    apt_fix_basic
  fi

  info "Plan mode: simulating install with temporary sources/keyring (no APT sources are modified)."
  ensure_deps_for_keyring

  local tmp
  tmp="$(mktemp -d)"
  chmod 700 "$tmp"
  local tmp_key="${tmp}/linuxmint-repo.gpg"

  # Create a temp keyring (never touches system keyring file)
  info "Preparing temporary Mint keyring for plan mode: ${tmp_key}"
  OVERWRITE_KEYRING="yes"
  RECREATE_KEYRING="yes"
  mint_repo_key_write_to "$tmp_key"

  detect_ubuntu_mirrors
  local tmp_sources="${tmp}/sources.list"
  cat > "$tmp_sources" <<EOF
deb [signed-by=${tmp_key}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  mkdir -p "${tmp}/lists" "${tmp}/cache" "${tmp}/prefs.d"
  cp -a /etc/apt/preferences.d/*.pref "${tmp}/prefs.d/" 2>/dev/null || true

  # Add our pinning into temp prefs
  cat > "${tmp}/prefs.d/50-linuxmint-conversion.pref" <<'EOF'
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 100

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome* mintinstall*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700
EOF
  cat > "${tmp}/prefs.d/51-linuxmint-desktop-stack.pref" <<'EOF'
Package: cinnamon* nemo* muffin* cjs* libcjs* libmuffin* libnemo-extension* nemo-* xapp* xapps-* slick-greeter* lightdm* mint-themes* mint-y-icons* mint-x-icons* pix* xviewer* cinnamon-settings-daemon* cinnamon-control-center* cinnamon-session* cinnamon-desktop-data* cinnamon-l10n* libcinnamon* gir1.2-cmenu-3.0 libcinnamon-menu-3-0*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF

  local pkgs
  mapfile -t pkgs < <(required_packages_for_convert)

  info "Running plan simulation..."
  export DEBIAN_FRONTEND=noninteractive

  # We must point apt at temp source list + temp lists/cache, but use real dpkg status.
  apt-get \
    -o "Dir::Etc::sourcelist=${tmp_sources}" \
    -o "Dir::Etc::sourceparts=-" \
    -o "Dir::Etc::PreferencesParts=${tmp}/prefs.d" \
    -o "Dir::State::Lists=${tmp}/lists" \
    -o "Dir::Cache=${tmp}/cache" \
    -o "Dir::State::status=/var/lib/dpkg/status" \
    -y update

  # Simulation install
  apt-get \
    -o "Dir::Etc::sourcelist=${tmp_sources}" \
    -o "Dir::Etc::sourceparts=-" \
    -o "Dir::Etc::PreferencesParts=${tmp}/prefs.d" \
    -o "Dir::State::Lists=${tmp}/lists" \
    -o "Dir::Cache=${tmp}/cache" \
    -o "Dir::State::status=/var/lib/dpkg/status" \
    -s $(apt_get_opts_common) install "${pkgs[@]}" \
    | tee "${LOG_DIR}/plan-$(date +%Y%m%d-%H%M%S).txt" >/dev/null

  ok "Plan mode complete. Temp dir preserved for review: ${tmp}"
}

###############################################################################
# Post-conversion validation (writes report file reliably)
###############################################################################
post_convert_validation() {
  local report="$1"
  : > "$report" || die "Unable to write report file: $report"

  local fail="no"
  {
    echo "Post-convert validation report: $(date -Is)"
    echo "Edition: ${EDITION}"
    echo "Ubuntu base: ${UBUNTU_BASE} | Mint target: ${TARGET_MINT}"
    echo
    echo "Keyring: ${KEYRING_OUT}"
    if [[ -r "$KEYRING_OUT" ]] && gpg --batch --quiet --show-keys "$KEYRING_OUT" >/dev/null 2>&1; then
      echo "  OK: keyring readable"
    else
      echo "  FAIL: keyring missing or unreadable"
      fail="yes"
    fi

    echo
    echo "Sources: ${SOURCES_OUT}"
    if [[ -r "$SOURCES_OUT" ]] && grep -q "packages.linuxmint.com" "$SOURCES_OUT"; then
      echo "  OK: sources file present"
    else
      echo "  FAIL: sources file missing or does not reference Mint"
      fail="yes"
    fi

    echo
    echo "APT health:"
    if apt-get -s check >/dev/null 2>&1; then
      echo "  OK: apt-get check"
    else
      echo "  WARN: apt-get check reports issues"
      fail="yes"
    fi

    echo
    echo "Display manager:"
    if systemctl is-enabled lightdm >/dev/null 2>&1; then
      echo "  OK: lightdm enabled"
    else
      echo "  WARN: lightdm not enabled"
      fail="yes"
    fi

    echo
    echo "Sessions present:"
    ls -1 /usr/share/xsessions 2>/dev/null | egrep -i 'cinnamon|mate|xfce|ubuntu|gnome' || true

    echo
    echo "Cinnamon helper sanity (if installed):"
    if [[ -x /usr/bin/csd-power ]]; then
      if /usr/bin/csd-power --help >/dev/null 2>&1; then
        echo "  OK: csd-power runnable"
      else
        echo "  FAIL: csd-power not runnable (may cause login loop)"
        echo "  Hint: ldd /usr/bin/csd-power ; journalctl -b _UID=\$UID"
        fail="yes"
      fi
    else
      echo "  NOTE: csd-power not found"
    fi

    echo
    echo "LightDM config:"
    grep -R --line-number -E 'user-session=|greeter-session=' /etc/lightdm 2>/dev/null || true
  } >> "$report"

  [[ "$fail" == "no" ]]
}

###############################################################################
# Convert mode (main)
###############################################################################
convert_mode() {
  require_root
  detect_os
  check_apt_locks
  convert_disclaimer_gate

  setup_logging

  if [[ "$AUTO_FIX" == "yes" ]]; then
    apt_fix_basic
  fi

  # Backup first (single, stable)
  BACKUP_DIR="$(backup_system_state)"
  ON_ERROR_BACKUP_HINT="sudo bash ${SCRIPT_NAME} rollback ${BACKUP_DIR}"

  timeshift_snapshot_best_effort

  if [[ "$KEEP_PPAS" != "yes" ]]; then
    disable_thirdparty_sources_system "$BACKUP_DIR"
  else
    warn "--keep-ppas enabled; leaving third-party sources intact (riskier)."
  fi

  # Keyring + sources + pinning
  mint_repo_key_install_system
  write_mint_sources_system
  write_mint_pinning_system
  remove_nosnap_pref_if_needed

  export DEBIAN_FRONTEND=noninteractive
  info "APT update..."
  apt-get -y update

  # Purge known conflicting Ubuntu flavor bits (especially ubuntucinnamon-environment)
  purge_conflicting_ubuntu_flavor_packages

  # Determine packages and run simulation first
  local pkgs
  mapfile -t pkgs < <(required_packages_for_convert)
  apt_simulate_install "${pkgs[@]}"

  # Install
  apt_install_mint_stack "${pkgs[@]}"

  # Re-run apt fix
  apt-get -y -f install || true
  apt-get -y --fix-broken install || true

  # Stage DM + session defaults
  set_display_manager_and_session_defaults

  # Best-effort fix for the csd-power/csd-color symbol issue + Xsession "has_option" breakage
  fix_cinnamon_symbol_rr_best_effort

  # Write post-convert report into backup dir
  local report="${BACKUP_DIR}/post-convert-validation.txt"
  info "Running post-conversion validation (report: ${report})"
  if post_convert_validation "$report"; then
    ok "Post-conversion validation PASSED."
    echo
    ok "Conversion complete."
    info "Reboot recommended."
    info "If you need rollback: sudo bash ${SCRIPT_NAME} rollback ${BACKUP_DIR}"
  else
    echo
    echo "${c_red}${c_bold}DO NOT REBOOT YET.${c_reset}"
    echo "${c_red}${c_bold}Post-conversion validation FAILED.${c_reset}"
    echo "Report: ${report}"
    echo "Log:    ${LOG_FILE}"
    echo
    echo "Suggested next steps:"
    echo "  1) Open the report and fix the failing items."
    echo "  2) If you need to revert APT sources immediately:"
    echo "       sudo bash ${SCRIPT_NAME} rollback ${BACKUP_DIR}"
    exit 2
  fi
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
      setup_logging
      parse_args "$@"
      plan_mode
      ;;
    convert)
      parse_args "$@"
      convert_mode
      ;;
    rollback)
      require_root
      setup_logging
      [[ $# -ge 1 ]] || die "rollback requires a backup directory path."
      rollback_from_backup "$1"
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
