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
#
# ----------------------------------------------------------------------
# Purpose:
#   Keep Ubuntu as the base OS and add Linux Mint repositories + install a
#   Mint desktop environment, while preserving corporate tooling as much
#   as possible.
#
# Supported:
#   Ubuntu 24.04 (noble) -> Linux Mint 22.x (default target: zena)
#   Ubuntu 22.04 (jammy) -> Linux Mint 21.x (default target: virginia)
#
# Modes:
#   doctor
#   plan
#   convert --i-accept-the-risk
#   rollback <backup_dir>
#
# X11/Wayland note:
#   This script defaults to an X11 session (safer for conversions/corp tooling).
#   You may pass --prefer-wayland, but since this script standardizes on LightDM
#   (Mint default), it will only select a Wayland session if it is actually
#   available as a LightDM-compatible Xsession. Otherwise it will warn and use X11.
# ----------------------------------------------------------------------

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_VERSION="4.2"

LOG_DIR="/var/log/ubuntu-to-mint"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ubuntu-to-mint-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

export LC_ALL=C

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; NC=$'\033[0m'
BOLD=$'\033[1m'

die() { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }
warn(){ echo "${YEL}WARN:${NC}  $*" >&2; }
info(){ echo "${BLU}INFO:${NC}  $*"; }
ok()  { echo "${GRN}OK:${NC}    $*"; }

# Optional: set to full fingerprint to hard-fail if it doesn't match.
# Example format: "0123456789ABCDEF0123456789ABCDEF01234567"
MINT_KEY_FPR_EXPECT="${MINT_KEY_FPR_EXPECT:-}"

ON_ERROR_BACKUP_HINT=""
on_err() {
  local line="${1:-?}" code="${2:-?}"
  echo "${RED}FAILED${NC} at line ${line} (exit ${code})." >&2
  echo "Command: ${BASH_COMMAND}" >&2
  [[ -n "${ON_ERROR_BACKUP_HINT}" ]] && echo "Rollback hint: ${ON_ERROR_BACKUP_HINT}" >&2
  echo "Log: ${LOG_FILE}" >&2
  exit "$code"
}
trap 'on_err "$LINENO" "$?"' ERR

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (use sudo)."; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

# -------------------------
# UNSUPPORTED DISCLAIMER GATE (CONVERT ONLY)
# -------------------------
require_unsupported_disclaimer() {
  local phrase="I UNDERSTAND THIS IS UNSUPPORTED"
  echo
  echo -e "${RED}${BOLD}======================================================================${NC}"
  echo -e "${RED}${BOLD}   UNSUPPORTED MIGRATION METHOD — PROBABLY A REALLY DUMB IDEA${NC}"
  echo -e "${RED}${BOLD}======================================================================${NC}"
  echo -e "${RED}${BOLD}This script attempts to graft Linux Mint repositories/packages onto Ubuntu.${NC}"
  echo -e "${RED}${BOLD}It is NOT supported by Linux Mint, Canonical, your IT department, or your employer.${NC}"
  echo -e "${RED}${BOLD}It can break APT, boot/login, device management, VPN/EDR, and leave the system unrecoverable.${NC}"
  echo -e "${RED}${BOLD}${NC}"
  echo -e "${RED}${BOLD}Recommended approach: do a CLEAN Linux Mint install and restore your data/apps from backup.${NC}"
  echo -e "${RED}${BOLD}If this is a corporate-managed device: STOP and get approval first.${NC}"
  echo -e "${RED}${BOLD}======================================================================${NC}"
  echo
  echo "To continue anyway, type exactly:"
  echo "  ${phrase}"
  echo "Anything else will abort."
  echo

  [[ -r /dev/tty ]] || die "No interactive TTY available (/dev/tty not readable). Refusing to proceed."
  local ans=""
  read -r -p "> " ans < /dev/tty || die "Unable to read confirmation from TTY."
  [[ "$ans" == "$phrase" ]] || die "Aborted."
  ok "Disclaimer acknowledged."
}

usage() {
  cat <<'EOF'
Usage:
  sudo bash ubuntu-to-mint-convert-v3.sh doctor [--auto-fix]
  sudo bash ubuntu-to-mint-convert-v3.sh plan   [--auto-fix] [--edition cinnamon|mate|xfce] [--target <mint_codename>] [--mint-mirror <url>] [--with-recommends]
  sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk [options...]
  sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS

Options:
  --i-accept-the-risk                   (required for convert)
  --edition cinnamon|mate|xfce          (default: cinnamon)
  --target  zena|zara|xia|wilma|virginia|victoria|vera|vanessa
  --mint-mirror URL                     (default: https://packages.linuxmint.com)
  --keep-ppas                           (do not disable 3rd-party repos; higher conflict risk)
  --allow-unhold                        (temporarily unhold packages during convert; risky)
  --preserve-snap                       (default: yes)
  --no-preserve-snap                    (disable snap-preservation behavior)
  --with-recommends                     (default: no; safer for corp systems)
  --overwrite-keyring                   (always overwrite Mint repo keyring file in-place)
  --recreate-keyring                    (move existing keyring aside and recreate from scratch)
  --auto-fix                            (doctor/plan only: allow dpkg/apt repairs and tool installs)
  --prefer-wayland                      (attempt to prefer a Wayland session if LightDM-compatible; otherwise warn and use X11)
  --yes                                 (skip interactive confirmation inside convert; does NOT bypass disclaimer)
EOF
}

# -------------------------
# Defaults / arg parsing
# -------------------------
MODE="${1:-}"
[[ -n "$MODE" ]] || { usage; exit 1; }
shift || true

ROLLBACK_DIR=""
if [[ "$MODE" == "rollback" ]]; then
  ROLLBACK_DIR="${1:-}"
  [[ -n "$ROLLBACK_DIR" ]] || die "rollback requires a backup dir argument."
  shift || true
fi

EDITION="cinnamon"
TARGET_MINT=""
MINT_MIRROR="https://packages.linuxmint.com"
KEEP_PPAS="no"
ALLOW_UNHOLD="no"
PRESERVE_SNAP="yes"
WITH_RECOMMENDS="no"
ASSUME_YES="no"
ACCEPT_RISK="no"
AUTO_FIX="no"
KEYRING_MODE="auto"   # auto|overwrite|recreate
PREFER_WAYLAND="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --i-accept-the-risk) ACCEPT_RISK="yes"; shift;;
    --edition) EDITION="${2:-}"; shift 2;;
    --target)  TARGET_MINT="${2:-}"; shift 2;;
    --mint-mirror) MINT_MIRROR="${2:-}"; shift 2;;
    --keep-ppas) KEEP_PPAS="yes"; shift;;
    --allow-unhold) ALLOW_UNHOLD="yes"; shift;;
    --preserve-snap) PRESERVE_SNAP="yes"; shift;;
    --no-preserve-snap) PRESERVE_SNAP="no"; shift;;
    --with-recommends) WITH_RECOMMENDS="yes"; shift;;
    --overwrite-keyring) KEYRING_MODE="overwrite"; shift;;
    --recreate-keyring) KEYRING_MODE="recreate"; shift;;
    --auto-fix) AUTO_FIX="yes"; shift;;
    --prefer-wayland) PREFER_WAYLAND="yes"; shift;;
    --yes) ASSUME_YES="yes"; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown arg: $1 (use --help)";;
  esac
done

validate_choice() {
  case "$1" in
    cinnamon|mate|xfce) ;;
    *) die "Invalid --edition '$1' (use cinnamon|mate|xfce)";;
  esac
}

validate_mirror() {
  [[ "$MINT_MIRROR" =~ ^https?:// ]] || die "--mint-mirror must start with http:// or https://"
}

read_os_release() {
  [[ -r /etc/os-release ]] || die "/etc/os-release missing"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_NAME="${NAME:-}"
  OS_VERSION_CODENAME="${VERSION_CODENAME:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
}

have_regular_file_or_die() {
  local p="$1"
  if [[ -e "$p" && ! -f "$p" ]]; then
    die "Expected regular file at '$p' but found non-regular (dir/symlink/device). Fix it before proceeding."
  fi
}

detect_ubuntu_codename() {
  local c=""
  if have_cmd lsb_release; then c="$(lsb_release -cs 2>/dev/null || true)"; fi
  [[ -n "$c" ]] || c="${OS_VERSION_CODENAME:-}"
  [[ -n "$c" ]] || die "Could not determine Ubuntu codename."
  echo "$c"
}

set_targets_from_ubuntu() {
  UBUNTU_CODENAME="$(detect_ubuntu_codename)"
  local -a ALLOWED_TARGETS=()
  case "$UBUNTU_CODENAME" in
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
      die "Unsupported Ubuntu codename '$UBUNTU_CODENAME'. Supports Ubuntu noble (24.04) or jammy (22.04) only."
      ;;
  esac

  [[ -n "$TARGET_MINT" ]] || TARGET_MINT="$DEFAULT_MINT"

  local ok_target="no"
  for t in "${ALLOWED_TARGETS[@]}"; do
    [[ "$TARGET_MINT" == "$t" ]] && ok_target="yes" && break
  done
  if [[ "$ok_target" != "yes" ]]; then
    local allowed_str
    printf -v allowed_str '%s ' "${ALLOWED_TARGETS[@]}"
    allowed_str="${allowed_str% }"
    die "--target '$TARGET_MINT' not allowed for Ubuntu '$UBUNTU_CODENAME'. Allowed: $allowed_str"
  fi
}

detect_ubuntu_mirrors() {
  local sources_txt=""
  if [[ -r /etc/apt/sources.list ]]; then
    sources_txt+="$(grep -E '^[[:space:]]*deb ' /etc/apt/sources.list || true)"$'\n'
  fi
  if compgen -G "/etc/apt/sources.list.d/*.list" >/dev/null; then
    sources_txt+="$(grep -RhsE '^[[:space:]]*deb ' /etc/apt/sources.list.d/*.list || true)"$'\n'
  fi
  if compgen -G "/etc/apt/sources.list.d/*.sources" >/dev/null; then
    sources_txt+="$(grep -RhsE '^[[:space:]]*URIs:[[:space:]]*' /etc/apt/sources.list.d/*.sources | awk '{print $2}' || true)"$'\n'
  fi

  UBUNTU_ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
  UBUNTU_SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

  local m
  m="$(echo "$sources_txt" | grep -Eo 'https?://[^ ]+/ubuntu' | head -n1 || true)"
  [[ -n "$m" ]] && UBUNTU_ARCHIVE_MIRROR="$m"

  info "Ubuntu archive mirror:  ${UBUNTU_ARCHIVE_MIRROR}"
  info "Ubuntu security mirror: ${UBUNTU_SECURITY_MIRROR}"
}

apt_fix_broken_overwrite() {
  DEBIAN_FRONTEND=noninteractive apt-get -y -f install \
    -o Dpkg::Options::=--force-overwrite \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold || true
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
  DEBIAN_FRONTEND=noninteractive apt-get -y -f install \
    -o Dpkg::Options::=--force-overwrite \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold || true
}

ensure_tools() {
  # ensure_tools <allow_changes yes|no> <tool1> <tool2> ...
  local allow="$1"; shift
  local missing=()
  local t
  for t in "$@"; do
    have_cmd "$t" || missing+=("$t")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi

  if [[ "$allow" == "yes" ]]; then
    info "Installing required tools: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -o Acquire::Retries=3
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg dirmngr
    for t in "$@"; do
      have_cmd "$t" || die "Tool install failed; still missing: $t"
    done
    return 0
  fi

  die "Missing required tools (${missing[*]}). Install them first or re-run with --auto-fix."
}

preflight_common() {
  # preflight_common <allow_changes yes|no>
  local allow_changes="$1"

  need_root
  validate_choice "$EDITION"
  validate_mirror
  read_os_release

  info "Script v${SCRIPT_VERSION}"
  info "Detected OS: ${OS_NAME} (ID=${OS_ID}, VERSION_ID=${OS_VERSION_ID}, CODENAME=${OS_VERSION_CODENAME})"
  [[ "$OS_ID" == "ubuntu" ]] || die "This script is intended for Ubuntu (ID=ubuntu). Detected ID=${OS_ID}."

  set_targets_from_ubuntu
  ok "Ubuntu base: ${UBUNTU_BASE} | Target Mint codename: ${TARGET_MINT} | Edition: ${EDITION} | Prefer Wayland: ${PREFER_WAYLAND}"

  for l in /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
    if [[ -e "$l" ]] && fuser "$l" >/dev/null 2>&1; then
      die "APT/DPKG lock is held ($l). Close updaters and try again."
    fi
  done

  if dpkg --audit | grep -q .; then
    if [[ "$allow_changes" == "yes" ]]; then
      warn "dpkg reports issues. Attempting to fix..."
      DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
      apt_fix_broken_overwrite
    else
      warn "dpkg reports issues (doctor/plan won't modify). Run: sudo dpkg --configure -a && sudo apt-get -f install"
    fi
  fi

  if ! apt-get check >/dev/null 2>&1; then
    if [[ "$allow_changes" == "yes" ]]; then
      warn "apt-get check failed. Attempting best-effort repair..."
      apt_fix_broken_overwrite
      apt-get check >/dev/null 2>&1 || warn "apt-get check still failing; conversion may fail."
    else
      warn "apt-get check failed (doctor/plan won't modify). Fix before converting."
    fi
  fi

  local root_free
  root_free="$(df -Pm / | awk 'NR==2{print $4}')"
  [[ "${root_free:-0}" -ge 6144 ]] || warn "Low free space on / (${root_free} MB). Recommend >= 6GB free."

  if [[ "$MODE" == "plan" || "$MODE" == "convert" ]]; then
    ensure_tools "$allow_changes" curl gpg
  else
    have_cmd curl || warn "curl not found (recommended)."
    have_cmd gpg  || warn "gpg not found (recommended)."
  fi

  if have_cmd curl; then
    curl -fsS --connect-timeout 10 --max-time 30 "${MINT_MIRROR%/}/" >/dev/null || warn "Cannot reach Mint mirror ${MINT_MIRROR} (may be blocked/proxy)."
  fi

  ok "Preflight completed."
}

# -------------------------
# Keyring helpers
# -------------------------
keyring_contains_keyid() {
  local keyring="$1"
  local keyid="${2^^}"

  [[ -s "$keyring" ]] || return 1
  have_regular_file_or_die "$keyring"
  have_cmd gpg || return 1

  local gh
  gh="$(mktemp -d)"
  chmod 700 "$gh"

  local found="no"
  if gpg --homedir "$gh" --batch --no-default-keyring --keyring "$keyring" --with-colons --list-keys 2>/dev/null \
      | awk -F: '$1=="pub"||$1=="sub"{print toupper($5)}' \
      | grep -q "${keyid}"; then
    found="yes"
  fi

  rm -rf "$gh"
  [[ "$found" == "yes" ]]
}

get_key_fingerprint_from_keyring() {
  local keyring="$1"
  have_cmd gpg || return 1
  [[ -s "$keyring" ]] || return 1

  local gh
  gh="$(mktemp -d)"
  chmod 700 "$gh"
  local fpr
  fpr="$(gpg --homedir "$gh" --batch --no-default-keyring --keyring "$keyring" --with-colons --list-keys 2>/dev/null \
        | awk -F: '$1=="fpr"{print toupper($10); exit}' || true)"
  rm -rf "$gh"
  [[ -n "$fpr" ]] || return 1
  echo "$fpr"
}

backup_existing_keyring() {
  local keyring="$1"
  local bdir="${LOG_DIR}/keyring-backups"
  mkdir -p "$bdir"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local dest="${bdir}/$(basename "$keyring").${ts}.bak"
  cp -a "$keyring" "$dest"
  ok "Backed up existing keyring to: $dest"
}

# -------------------------
# Key handling (HKPS -> HKP:80 -> HTTPS fallback) + atomic write (same dir)
# -------------------------
mint_repo_key_write_to() {
  # mint_repo_key_write_to <out_keyring> <allow_changes yes|no>
  local out_keyring="$1"
  local allow_changes="${2:-no}"
  local keyid="A6616109451BBBF2"

  [[ -n "$out_keyring" ]] || die "mint_repo_key_write_to requires an output path"
  ensure_tools "$allow_changes" curl gpg

  local out_dir
  out_dir="$(dirname "$out_keyring")"
  mkdir -p "$out_dir"

  # Atomicity: temp file in SAME directory as out_keyring
  local tmp_out
  tmp_out="$(mktemp -p "$out_dir" ".linuxmint-repo.gpg.tmp.XXXXXX")"
  chmod 600 "$tmp_out"

  local gnupghome
  gnupghome="$(mktemp -d)"
  chmod 700 "$gnupghome"

  local -a ks_opts=()
  if [[ -n "${http_proxy:-}" ]]; then
    ks_opts+=(--keyserver-options "http-proxy=${http_proxy}")
  elif [[ -n "${https_proxy:-}" ]]; then
    ks_opts+=(--keyserver-options "http-proxy=${https_proxy}")
  fi

  local got="no"
  if gpg --homedir "$gnupghome" --batch "${ks_opts[@]}" --keyserver hkps://keyserver.ubuntu.com --recv-keys "$keyid" >/dev/null 2>&1; then
    got="yes"
  elif gpg --homedir "$gnupghome" --batch "${ks_opts[@]}" --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "$keyid" >/dev/null 2>&1; then
    got="yes"
  else
    got="no"
  fi

  if [[ "$got" == "yes" ]]; then
    if ! gpg --homedir "$gnupghome" --batch --export "$keyid" | gpg --batch --dearmor -o "$tmp_out"; then
      rm -rf "$gnupghome"
      rm -f "$tmp_out"
      die "Failed to export+dearmor the Mint repo key from keyserver results."
    fi
  else
    info "Keyserver blocked; fetching key over HTTPS from Ubuntu keyserver (exact match)..."
    local armored="$gnupghome/linuxmint-repo.asc"

    if ! curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${keyid}&exact=on" -o "$armored"; then
      curl -fsSL --connect-timeout 10 --max-time 30 \
        "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${keyid}&exact=on" -o "$armored" \
        || die "Unable to fetch Mint repo key via keyserver or HTTPS fallback."
    fi

    grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$armored" \
      || die "Downloaded key is not a PGP public key block (proxy portal/HTML?)"

    local found="no"
    while IFS= read -r kid; do
      [[ "${kid^^}" == "${keyid^^}" ]] && found="yes" && break
    done < <(gpg --batch --with-colons --show-keys "$armored" | awk -F: '$1=="pub"||$1=="sub"{print $5}')

    [[ "$found" == "yes" ]] || die "Fetched key does not contain expected keyid ${keyid^^}"

    gpg --batch --dearmor -o "$tmp_out" "$armored"
  fi

  chmod 644 "$tmp_out"
  mv -f "$tmp_out" "$out_keyring"
  chmod 644 "$out_keyring"
  rm -rf "$gnupghome"

  # Post-write fingerprint logging + optional hard check
  local fpr
  fpr="$(get_key_fingerprint_from_keyring "$out_keyring" || true)"
  [[ -n "$fpr" ]] || die "Unable to read fingerprint from written keyring: $out_keyring"
  info "Mint repo key fingerprint installed: $fpr"

  if [[ -n "$MINT_KEY_FPR_EXPECT" ]]; then
    [[ "${fpr^^}" == "${MINT_KEY_FPR_EXPECT^^}" ]] || die "Mint key fingerprint mismatch. Expected ${MINT_KEY_FPR_EXPECT^^}, got ${fpr^^}"
  fi
}

mint_repo_key_install() {
  local keyring="/usr/share/keyrings/linuxmint-repo.gpg"
  local keyid="A6616109451BBBF2"

  have_regular_file_or_die "$keyring"

  if [[ -e "$keyring" ]]; then
    case "$KEYRING_MODE" in
      recreate)
        warn "Mint keyring already exists at ${keyring}; recreating as requested."
        [[ -s "$keyring" ]] && backup_existing_keyring "$keyring" || true
        rm -f "$keyring"
        ;;
      overwrite)
        warn "Mint keyring already exists at ${keyring}; overwriting in-place as requested."
        ;;
      auto)
        if [[ -s "$keyring" ]] && keyring_contains_keyid "$keyring" "$keyid"; then
          ok "Mint keyring already present and contains expected key (${keyid})."
          return 0
        fi
        warn "Mint keyring exists but is missing/invalid or does not contain expected key (${keyid}); recreating safely."
        [[ -s "$keyring" ]] && backup_existing_keyring "$keyring" || true
        rm -f "$keyring"
        ;;
      *)
        die "Internal error: unknown KEYRING_MODE=${KEYRING_MODE}"
        ;;
    esac
  fi

  info "Installing Linux Mint repo signing key into ${keyring}"
  mint_repo_key_write_to "$keyring" "yes"
  [[ -s "$keyring" ]] || die "Mint keyring did not get created at ${keyring}"

  if ! keyring_contains_keyid "$keyring" "$keyid"; then
    backup_existing_keyring "$keyring" || true
    die "Mint keyring created but does not contain expected key (${keyid})."
  fi

  ok "Key installed."
}

# -------------------------
# APT sources/pinning
# -------------------------
disable_ubuntu_sources_if_present() {
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    local new="/etc/apt/sources.list.d/ubuntu.sources.disabled.ubuntu-to-mint"
    info "Disabling existing ubuntu.sources to avoid duplicate entries: ${new}"
    mv -f /etc/apt/sources.list.d/ubuntu.sources "$new" || true
  fi
}

write_mint_sources_system() {
  local list="/etc/apt/sources.list.d/official-package-repositories.list"
  local keyring="/usr/share/keyrings/linuxmint-repo.gpg"

  [[ -s "$keyring" ]] || die "Missing keyring ${keyring}. Run key install first."

  detect_ubuntu_mirrors
  disable_ubuntu_sources_if_present

  info "Writing Mint+Ubuntu sources to ${list}"
  cat > "$list" <<EOF
# Do not edit this file manually.
# Generated by ubuntu-to-mint-convert-v3.sh on $(date -Is)
#
# Linux Mint repository:
deb [signed-by=${keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport

# Ubuntu base repositories:
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^[[:space:]]*deb /# deb /' /etc/apt/sources.list || true
  fi

  ok "Sources written."
}

write_mint_pinning_system() {
  local pref="/etc/apt/preferences.d/50-linuxmint-conversion.pref"
  info "Writing APT pinning to ${pref}"

  cat > "$pref" <<'EOF'
Package: *
Pin: release o=LinuxMint
Pin-Priority: 100

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: release o=LinuxMint
Pin-Priority: 700

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700

Package: cinnamon* nemo* muffin* cjs* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: release o=LinuxMint
Pin-Priority: 900

Package: cinnamon* nemo* muffin* cjs* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 900

Package: python3-xapp* python-xapp* libxapp* gir1.2-xapp* xapps* xapps-common xapp-symbolic-icons xapp-status-icon
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: python3-xapp* python-xapp* libxapp* gir1.2-xapp* xapps* xapps-common xapp-symbolic-icons xapp-status-icon
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: libnemo-extension1* nemo-data*
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: libnemo-extension1* nemo-data*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: libcinnamon-control-center1* libcinnamon-menu-3-0* libcinnamon-desktop4* cinnamon-desktop-data* cinnamon-control-center-data* cinnamon-l10n*
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: libcinnamon-control-center1* libcinnamon-menu-3-0* libcinnamon-desktop4* cinnamon-desktop-data* cinnamon-control-center-data* cinnamon-l10n*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF

  ok "Pinning written."
}

# -------------------------
# 3rd-party repo handling (preserve Falcon/GlobalProtect/etc)
# -------------------------
disable_thirdparty_sources_system() {
  local backup_dir="$1"
  local disabled_dir="${backup_dir}/disabled-sources"
  mkdir -p "$disabled_dir"

  info "Disabling 3rd-party sources into: ${disabled_dir}"
  shopt -s nullglob

  local allow_re='(crowdstrike|falcon|globalprotect|paloalto|pan(gp)?|cortex|prisma)'

  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ "$(basename "$f")" == "official-package-repositories.list" ]] && continue
    if echo "$(basename "$f")" | grep -Eiq "$allow_re" || grep -Eiq "$allow_re" "$f"; then
      info "Preserving vendor repo: $f"
      continue
    fi
    mv -v "$f" "${disabled_dir}/" || true
  done

  shopt -u nullglob
  ls -1 "${disabled_dir}" 2>/dev/null | sed 's/^/  disabled: /' | tee -a "${backup_dir}/disabled-sources.txt" >/dev/null || true
  ok "Third-party sources disabled (restorable via rollback)."
}

# -------------------------
# dpkg-divert for known conflicts
# -------------------------
apply_known_diversions() {
  local f="/usr/share/icons/hicolor/16x16/apps/software-properties.png"
  if dpkg-query -W -f='${Status}' software-properties-gtk 2>/dev/null | grep -q "installed"; then
    if dpkg -S "$f" 2>/dev/null | grep -q "^software-properties-gtk:"; then
      info "Applying dpkg-divert for known conflict: $f"
      dpkg-divert --package ubuntu-to-mint-convert --rename --add "$f" || true
    fi
  fi
}

# -------------------------
# Backup / snapshot
# -------------------------
backup_system_state() {
  local backup_dir="/root/ubuntu-to-mint-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  ON_ERROR_BACKUP_HINT="sudo bash $0 rollback ${backup_dir}"

  info "Creating backup at: ${backup_dir}"
  mkdir -p "${backup_dir}/etc"
  cp -a /etc/apt "${backup_dir}/etc/" || true
  cp -a /etc/os-release /etc/lsb-release 2>/dev/null "${backup_dir}/etc/" || true

  mkdir -p "${backup_dir}/etc/X11" "${backup_dir}/etc/lightdm"
  cp -a /etc/X11/default-display-manager 2>/dev/null "${backup_dir}/etc/X11/" || true
  cp -a /etc/lightdm 2>/dev/null "${backup_dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${backup_dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${backup_dir}/apt-manual.txt" || true
  apt-mark showhold > "${backup_dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${backup_dir}/enabled-services.txt" || true

  ok "Backup complete."
  echo "$backup_dir"
}

timeshift_snapshot_best_effort() {
  if have_cmd timeshift; then
    info "Timeshift detected. Attempting pre-change snapshot (best-effort)..."
    timeshift --create --comments "pre ubuntu->mint $(date -Is)" --tags D || warn "Timeshift snapshot failed (may not be configured)."
  else
    warn "Timeshift not installed. Strongly recommended to snapshot/backup before converting."
  fi
}

# -------------------------
# apt-get with tee but correct exit status
# -------------------------
run_apt_tee() {
  local outfile="$1"; shift
  local old_trap
  old_trap="$(trap -p ERR || true)"
  trap - ERR
  set +e

  DEBIAN_FRONTEND=noninteractive apt-get "$@" 2>&1 | tee "$outfile"
  local rc="${PIPESTATUS[0]}"

  set -e
  if [[ -n "$old_trap" ]]; then eval "$old_trap"; else trap 'on_err "$LINENO" "$?"' ERR; fi
  return "$rc"
}

parse_and_guard_apt_actions() {
  local sim_output_file="$1"
  [[ -r "$sim_output_file" ]] || die "Missing simulation output: $sim_output_file"

  local removed removed_count
  removed="$(grep -E '^Remv ' "$sim_output_file" | awk '{print $2}' || true)"
  removed_count="$(echo "$removed" | grep -c . || true)"

  info "APT simulation: packages marked for removal: ${removed_count}"

  local critical_re='^(sudo|openssh-server|ssh|network-manager|systemd|systemd-sysv|dbus|polkit|linux-image|linux-generic|linux-modules|grub|grub2|initramfs-tools|libc6|libstdc\+\+6|snapd|netplan\.io|systemd-resolved)$'
  local bad=""
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" =~ $critical_re ]] && bad+="$p"$'\n'
  done <<< "$removed"

  if [[ -n "$bad" ]]; then
    echo "$bad" | sed 's/^/  - /'
    die "Refusing to proceed: simulation removes critical packages above."
  fi

  if [[ "$removed_count" -gt 25 ]]; then
    die "Refusing to proceed: too many removals (${removed_count}). Inspect conflicts."
  fi

  ok "Guard rails passed."
}

# -------------------------
# Desktop / Display Manager defaults (prefer X11 by default)
# -------------------------
find_session_name_for_edition() {
  local desired="$1"
  local prefer_wayland="$2"  # yes|no
  local xs="/usr/share/xsessions"
  local ws="/usr/share/wayland-sessions"

  [[ -d "$xs" ]] || die "Missing $xs (no X sessions installed?)."

  local sess=""

  # If user asked for Wayland, try to find a LightDM-compatible session FIRST.
  # Note: Most Wayland sessions ship under /usr/share/wayland-sessions and are
  # typically intended for GDM. Since this script standardizes on LightDM, we only
  # select Wayland if it appears as an Xsession.
  if [[ "$prefer_wayland" == "yes" ]]; then
    local -a way_candidates=()
    case "$desired" in
      cinnamon) way_candidates=(cinnamon-wayland) ;;
      mate)     way_candidates=() ;;
      xfce)     way_candidates=() ;;
    esac

    local c
    for c in "${way_candidates[@]}"; do
      if [[ -f "$xs/${c}.desktop" ]]; then
        sess="$c"
        echo "$sess"
        return 0
      fi
      if [[ -d "$ws" && -f "$ws/${c}.desktop" ]]; then
        warn "Wayland session '${c}' exists in ${ws}, but LightDM may not support it. Falling back to X11."
      fi
    done
  fi

  # Default / safer: X11 session candidates
  local -a candidates=()
  case "$desired" in
    cinnamon) candidates=(cinnamon cinnamon2d) ;;
    mate)     candidates=(mate) ;;
    xfce)     candidates=(xfce xfce4) ;;
    *)        candidates=("$desired") ;;
  esac

  local c
  for c in "${candidates[@]}"; do
    [[ -f "$xs/${c}.desktop" ]] && sess="$c" && break
  done

  [[ -n "$sess" ]] || sess="$desired"
  echo "$sess"
}

set_mint_defaults_display_manager_and_session() {
  local dm_pkg="lightdm"
  local greeter="slick-greeter"
  local session
  session="$(find_session_name_for_edition "$EDITION" "$PREFER_WAYLAND")"

  if [[ "$PREFER_WAYLAND" == "yes" && "$session" != *wayland* ]]; then
    warn "--prefer-wayland was set, but no LightDM-compatible Wayland session was found; using X11 session '${session}'."
  fi

  info "Staging defaults (apply fully after reboot): DM=${dm_pkg}, greeter=${greeter}, session=${session}"

  DEBIAN_FRONTEND=noninteractive apt-get -y install "${dm_pkg}" "${greeter}"

  local dm_path
  dm_path="$(command -v lightdm 2>/dev/null || true)"
  [[ -n "$dm_path" ]] || dm_path="/usr/sbin/lightdm"
  [[ -x "$dm_path" ]] || die "LightDM binary not found/executable at: $dm_path"

  mkdir -p /etc/X11
  echo "${dm_path}" > /etc/X11/default-display-manager

  if have_cmd debconf-set-selections; then
    for owner in gdm3 lightdm sddm; do
      dpkg-query -W -f='${Status}' "$owner" 2>/dev/null | grep -q "installed" || continue
      echo "${owner} shared/default-x-display-manager select lightdm" | debconf-set-selections || true
    done
    echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true
  fi

  mkdir -p /etc/lightdm/lightdm.conf.d
  cat > /etc/lightdm/lightdm.conf.d/60-mint-defaults.conf <<EOF
[Seat:*]
greeter-session=${greeter}
user-session=${session}
EOF

  systemctl disable gdm3 2>/dev/null || true
  systemctl disable sddm 2>/dev/null || true
  systemctl unmask lightdm.service 2>/dev/null || true
  systemctl enable lightdm.service 2>/dev/null || systemctl enable lightdm 2>/dev/null || true

  ok "Defaults staged: lightdm + ${session}"
}

# -------------------------
# Post-conversion validation
# -------------------------
is_enabled_any() { systemctl is-enabled "$1" >/dev/null 2>&1; }
is_active_any() { systemctl is-active "$1"  >/dev/null 2>&1; }

detect_first_matching_unit() {
  local re="$1"
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei "$re" | head -n1 || true
}

post_convert_validate_or_die() {
  local backup_dir="$1"
  local report="${backup_dir}/post-convert-validation.txt"
  : > "$report"

  v() { echo "$*" | tee -a "$report" >/dev/null; }

  local failed=0
  local session
  session="$(find_session_name_for_edition "$EDITION" "$PREFER_WAYLAND")"

  info "Running post-conversion validation (report: ${report})"

  v "=== Post-Conversion Validation ==="
  v "Timestamp: $(date -Is)"
  v "Edition:   ${EDITION}"
  v "Session:   ${session}"
  v "PreferWL:  ${PREFER_WAYLAND}"
  v "---------------------------------"

  if [[ -f "/usr/share/xsessions/${session}.desktop" ]]; then
    v "OK: session desktop file exists: /usr/share/xsessions/${session}.desktop"
  else
    v "FAIL: missing session desktop file: /usr/share/xsessions/${session}.desktop"
    failed=1
  fi

  if [[ "$PREFER_WAYLAND" != "yes" && "$session" == *wayland* ]]; then
    v "WARN: selected session appears to be Wayland despite X11 preference: ${session}"
  fi

  if [[ -r /etc/X11/default-display-manager ]]; then
    local dm_path
    dm_path="$(cat /etc/X11/default-display-manager 2>/dev/null || true)"
    if [[ "$dm_path" =~ lightdm ]] && [[ -x "$dm_path" ]]; then
      v "OK: default display manager set to: ${dm_path}"
    else
      v "FAIL: /etc/X11/default-display-manager is '${dm_path}' (expected executable lightdm path)"
      failed=1
    fi
  else
    v "FAIL: missing /etc/X11/default-display-manager"
    failed=1
  fi

  if is_enabled_any lightdm.service || is_enabled_any lightdm; then
    v "OK: lightdm is enabled for next boot"
  else
    v "FAIL: lightdm is NOT enabled"
    failed=1
  fi

  if is_active_any NetworkManager.service || is_active_any network-manager.service; then
    v "OK: NetworkManager is active"
  else
    v "FAIL: NetworkManager is NOT active"
    failed=1
  fi

  if apt-get check >/dev/null 2>&1; then
    v "OK: apt-get check passed"
  else
    v "FAIL: apt-get check failed"
    failed=1
  fi

  local snapd_installed="no"
  if dpkg-query -W -f='${Status}' snapd 2>/dev/null | grep -q "installed"; then
    snapd_installed="yes"
  fi

  if [[ "$PRESERVE_SNAP" == "yes" && "$snapd_installed" == "yes" ]]; then
    if is_enabled_any snapd.service || is_enabled_any snapd.socket; then
      v "OK: snapd is enabled (service or socket)"
    else
      v "FAIL: snapd is installed but not enabled (service/socket)"
      failed=1
    fi
  else
    v "INFO: snapd check skipped (preserve-snap=${PRESERVE_SNAP}, snapd_installed=${snapd_installed})"
  fi

  local falcon_detect="no"
  [[ -d /opt/CrowdStrike ]] && falcon_detect="yes"
  [[ -x /opt/CrowdStrike/falconctl ]] && falcon_detect="yes"

  local falcon_unit
  falcon_unit="$(detect_first_matching_unit 'falcon(-sensor)?\.service|crowdstrike|falcon')"

  if [[ "$falcon_detect" == "yes" || -n "$falcon_unit" ]]; then
    v "INFO: CrowdStrike detected (unit=${falcon_unit:-none})"
    if [[ -n "$falcon_unit" ]]; then
      if is_enabled_any "$falcon_unit"; then v "OK: ${falcon_unit} is enabled"; else v "FAIL: ${falcon_unit} is NOT enabled"; failed=1; fi
      if is_active_any "$falcon_unit"; then v "OK: ${falcon_unit} is active"; else v "FAIL: ${falcon_unit} is NOT active"; failed=1; fi
    else
      if pgrep -fa 'falcon' >/dev/null 2>&1; then
        v "OK: CrowdStrike process detected (no unit found, but processes are running)"
      else
        v "FAIL: CrowdStrike files detected but no unit found and no falcon process running"
        failed=1
      fi
    fi
  else
    v "INFO: CrowdStrike not detected (skipping)"
  fi

  local gp_detect="no"
  [[ -d /opt/paloaltonetworks/globalprotect ]] && gp_detect="yes"
  [[ -x /opt/paloaltonetworks/globalprotect/PanGPS ]] && gp_detect="yes"

  local gp_unit
  gp_unit="$(detect_first_matching_unit 'gpd\.service|pangps\.service|globalprotect|pan(gp|gps)')"

  if [[ "$gp_detect" == "yes" || -n "$gp_unit" ]]; then
    v "INFO: GlobalProtect detected (unit=${gp_unit:-none})"
    if [[ -x /opt/paloaltonetworks/globalprotect/PanGPS ]]; then
      v "OK: PanGPS binary present"
    else
      v "FAIL: PanGPS binary missing at /opt/paloaltonetworks/globalprotect/PanGPS"
      failed=1
    fi

    if [[ -n "$gp_unit" ]]; then
      if is_enabled_any "$gp_unit"; then
        v "OK: ${gp_unit} is enabled"
      else
        v "FAIL: ${gp_unit} is NOT enabled"
        failed=1
      fi
      if is_active_any "$gp_unit"; then
        v "OK: ${gp_unit} is active"
      else
        v "FAIL: ${gp_unit} is NOT active (VPN may fail to connect after reboot)"
        failed=1
      fi
    else
      if pgrep -x PanGPS >/dev/null 2>&1 || pgrep -x PanGPA >/dev/null 2>&1; then
        v "OK: GlobalProtect processes detected (no unit found)"
      else
        v "WARN: No GlobalProtect unit found and no PanGPS/PanGPA process running (may be normal if not connected)"
      fi
    fi
  else
    v "INFO: GlobalProtect not detected (skipping)"
  fi

  if [[ -r /etc/lightdm/lightdm.conf.d/60-mint-defaults.conf ]]; then
    if grep -q "user-session=${session}" /etc/lightdm/lightdm.conf.d/60-mint-defaults.conf; then
      v "OK: LightDM default session configured to ${session}"
    else
      v "FAIL: LightDM defaults file does not set user-session=${session}"
      failed=1
    fi
    if grep -q "greeter-session=slick-greeter" /etc/lightdm/lightdm.conf.d/60-mint-defaults.conf; then
      v "OK: LightDM greeter configured to slick-greeter"
    else
      v "FAIL: LightDM defaults file does not set greeter-session=slick-greeter"
      failed=1
    fi
  else
    v "FAIL: missing /etc/lightdm/lightdm.conf.d/60-mint-defaults.conf"
    failed=1
  fi

  if [[ "$failed" -ne 0 ]]; then
    echo
    echo "${RED}${BOLD}DO NOT REBOOT YET.${NC}"
    echo "${RED}${BOLD}Post-conversion validation FAILED.${NC}"
    echo "Report: ${report}"
    echo "Log:    ${LOG_FILE}"
    echo
    echo "Suggested next steps:"
    echo "  1) Open the report and fix the failing items."
    echo "  2) If you need to revert APT sources immediately:"
    echo "       ${ON_ERROR_BACKUP_HINT}"
    echo
    exit 12
  fi

  ok "Post-conversion validation passed."
}

# -------------------------
# Plan mode (temp APT env)
# -------------------------
apt_simulate_with_temp_sources() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mkdir -p "$tmp/etc"
  cp -a /etc/apt "$tmp/etc/"

  mkdir -p "$tmp/usr/share/keyrings"
  local temp_keyring="$tmp/usr/share/keyrings/linuxmint-repo.gpg"
  info "Plan mode: creating temporary Mint keyring at $temp_keyring"
  mint_repo_key_write_to "$temp_keyring" "no"

  detect_ubuntu_mirrors

  cat > "$tmp/etc/apt/sources.list" <<EOF
deb [signed-by=${temp_keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  mkdir -p "$tmp/etc/apt/preferences.d"
  # Use the same pinning logic as convert
  cat > "$tmp/etc/apt/preferences.d/50-linuxmint-conversion.pref" <<'EOF'
Package: *
Pin: release o=LinuxMint
Pin-Priority: 100

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: release o=LinuxMint
Pin-Priority: 700

Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintlocale* mintdrivers* mintreport* mintwelcome*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700

Package: cinnamon* nemo* muffin* cjs* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: release o=LinuxMint
Pin-Priority: 900

Package: cinnamon* nemo* muffin* cjs* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 900

Package: python3-xapp* python-xapp* libxapp* gir1.2-xapp* xapps* xapps-common xapp-symbolic-icons xapp-status-icon
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: python3-xapp* python-xapp* libxapp* gir1.2-xapp* xapps* xapps-common xapp-symbolic-icons xapp-status-icon
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: libnemo-extension1* nemo-data*
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: libnemo-extension1* nemo-data*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001

Package: libcinnamon-control-center1* libcinnamon-menu-3-0* libcinnamon-desktop4* cinnamon-desktop-data* cinnamon-control-center-data* cinnamon-l10n*
Pin: release o=LinuxMint
Pin-Priority: 1001

Package: libcinnamon-control-center1* libcinnamon-menu-3-0* libcinnamon-desktop4* cinnamon-desktop-data* cinnamon-control-center-data* cinnamon-l10n*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 1001
EOF

  mkdir -p "$tmp/var/lib/apt/lists/partial" "$tmp/var/cache/apt/archives/partial"

  local recommends="--no-install-recommends"
  [[ "$WITH_RECOMMENDS" == "yes" ]] && recommends=""

  local -a pkgs=()
  case "$EDITION" in
    cinnamon) pkgs+=(mint-meta-cinnamon) ;;
    mate)     pkgs+=(mint-meta-mate) ;;
    xfce)     pkgs+=(mint-meta-xfce) ;;
  esac
  pkgs+=(mint-meta-core mint-meta-codecs mintsystem mintupdate mintsources)

  info "Plan mode: apt update (temporary dirs)..."
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dir::Etc="$tmp/etc/apt" \
    -o Dir::Etc::sourceparts="-" \
    -o Dir::State="$tmp/var/lib/apt" \
    -o Dir::Cache="$tmp/var/cache/apt" \
    -o Dir::State::status="/var/lib/dpkg/status" \
    -o Acquire::Retries=3 \
    update

  local plan_log="$LOG_DIR/plan-$(date +%Y%m%d-%H%M%S).txt"
  info "Plan mode: simulated install: ${pkgs[*]}"
  if ! run_apt_tee "$plan_log" \
      -o Dir::Etc="$tmp/etc/apt" \
      -o Dir::Etc::sourceparts="-" \
      -o Dir::State="$tmp/var/lib/apt" \
      -o Dir::Cache="$tmp/var/cache/apt" \
      -o Dir::State::status="/var/lib/dpkg/status" \
      -o Acquire::Retries=3 \
      -s install $recommends "${pkgs[@]}"; then
    tail -n 160 "$plan_log" >&2 || true
    die "Plan simulation failed. See: $plan_log"
  fi

  ok "Plan completed. Review: $plan_log"
}

# -------------------------
# Convert mode
# -------------------------
convert_apply() {
  [[ "$ACCEPT_RISK" == "yes" ]] || die "You must pass --i-accept-the-risk to run convert."

  # Disclaimer is required only for convert (per request)
  require_unsupported_disclaimer

  preflight_common "yes"

  if [[ "$ASSUME_YES" != "yes" ]]; then
    echo
    warn "This can break a corporate-managed machine. Ensure you have approval + a rollback plan."
    echo "Target: Ubuntu ${UBUNTU_BASE} -> Mint ${TARGET_MINT} (${EDITION})"
    read -r -p "Type 'I UNDERSTAND' to continue: " ans
    [[ "$ans" == "I UNDERSTAND" ]] || die "Aborted by user."
  fi

  local backup_dir
  backup_dir="$(backup_system_state)"
  timeshift_snapshot_best_effort

  local held
  held="$(apt-mark showhold || true)"
  if [[ -n "$held" ]]; then
    warn "Held packages detected:"
    echo "$held" | sed 's/^/  HOLD: /'
    if [[ "$ALLOW_UNHOLD" == "yes" ]]; then
      info "Saving holds list to ${backup_dir}/held-packages.txt and temporarily unholding..."
      echo "$held" > "${backup_dir}/held-packages.txt"
      # shellcheck disable=SC2086
      apt-mark unhold $held
    else
      die "Held packages will block dependency resolution. Resolve holds or re-run with --allow-unhold."
    fi
  fi

  # Preseed display manager selection early (reduces DM prompt/flip-flops)
  DEBIAN_FRONTEND=noninteractive apt-get -y install debconf-utils || true
  if have_cmd debconf-set-selections; then
    echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true
  fi

  systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
  systemctl kill --kill-who=all apt-daily.service apt-daily-upgrade.service 2>/dev/null || true

  if [[ "$KEEP_PPAS" != "yes" ]]; then
    disable_thirdparty_sources_system "$backup_dir"
  else
    warn "--keep-ppas set. Proceeding with third-party sources enabled may increase conflict risk."
  fi

  mint_repo_key_install
  write_mint_sources_system
  write_mint_pinning_system

  info "APT update..."
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update

  if ! apt-cache show mint-meta-core >/dev/null 2>&1; then
    die "Mint repo not usable: apt cannot see 'mint-meta-core'. Check mirror/key/network."
  fi

  local recommends="--no-install-recommends"
  [[ "$WITH_RECOMMENDS" == "yes" ]] && recommends=""

  local -a pkgs=()
  case "$EDITION" in
    cinnamon) pkgs+=(mint-meta-cinnamon) ;;
    mate)     pkgs+=(mint-meta-mate) ;;
    xfce)     pkgs+=(mint-meta-xfce) ;;
  esac
  pkgs+=(mint-meta-core mintsystem mintupdate mintsources mint-meta-codecs)

  info "Simulation (safety check) of install: ${pkgs[*]}"
  local sim_out="${backup_dir}/apt-sim-install.txt"
  if ! run_apt_tee "$sim_out" -s install $recommends "${pkgs[@]}"; then
    tail -n 200 "$sim_out" >&2 || true
    die "APT simulation failed. See: $sim_out"
  fi
  parse_and_guard_apt_actions "$sim_out"

  apply_known_diversions

  info "Installing Mint packages..."
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  if ! apt-get -y install \
      -o Dpkg::Options::=--force-overwrite \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      $recommends \
      "${pkgs[@]}"; then
    warn "Initial install hit errors; attempting fix-broken with overwrite smoothing..."
    apt_fix_broken_overwrite
    apt-get -y install \
      -o Dpkg::Options::=--force-overwrite \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      $recommends \
      "${pkgs[@]}"
  fi

  if [[ "$PRESERVE_SNAP" == "yes" ]]; then
    local nosnap="/etc/apt/preferences.d/nosnap.pref"
    if [[ -f "$nosnap" ]]; then
      warn "Mint 'nosnap' preference detected at ${nosnap}. Removing to preserve snap functionality."
      rm -f "$nosnap"
      DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update
    fi
  fi

  set_mint_defaults_display_manager_and_session

  if [[ -f "${backup_dir}/held-packages.txt" ]]; then
    info "Re-applying package holds from ${backup_dir}/held-packages.txt"
    # shellcheck disable=SC2046
    apt-mark hold $(cat "${backup_dir}/held-packages.txt") || true
  fi

  post_convert_validate_or_die "$backup_dir"

  ok "Conversion completed successfully."
  info "Backup dir: ${backup_dir}"
  info "Log file:   ${LOG_FILE}"
  echo
  echo "Next steps:"
  echo "  1) Reboot (required for display manager/session defaults to fully apply)."
  echo "  2) Validate corp software end-to-end: VPN, EDR, SSO, printers, etc."
}

# -------------------------
# Rollback mode: restore /etc/apt from backup (does NOT remove installed packages)
# -------------------------
rollback_apply() {
  need_root
  local backup_dir="$1"
  [[ -n "$backup_dir" ]] || die "rollback requires a backup dir argument."
  [[ -d "$backup_dir" ]] || die "No such backup dir: $backup_dir"
  [[ -d "${backup_dir}/etc/apt" ]] || die "Backup dir missing etc/apt: $backup_dir"

  if [[ "$backup_dir" != /root/ubuntu-to-mint-backup-* ]]; then
    warn "Backup dir does not match expected pattern /root/ubuntu-to-mint-backup-*. Proceeding anyway."
  fi

  info "Restoring /etc/apt from backup: ${backup_dir}/etc/apt"
  if [[ -d /etc/apt ]]; then
    mv /etc/apt "/etc/apt.pre-rollback.$(date +%Y%m%d-%H%M%S)" || true
  fi
  cp -a "${backup_dir}/etc/apt" /etc/apt

  if [[ -d "${backup_dir}/disabled-sources" ]]; then
    info "Restoring disabled sources from ${backup_dir}/disabled-sources"
    mkdir -p /etc/apt/sources.list.d
    cp -a "${backup_dir}/disabled-sources/." /etc/apt/sources.list.d/ || true
  fi

  info "APT update after rollback..."
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update || true
  ok "Rollback of APT configuration completed."
  info "Note: This does NOT automatically remove Mint-installed packages. Use Timeshift/snapshot to fully revert system state."
}

main() {
  case "$MODE" in
    doctor)
      preflight_common "$AUTO_FIX"
      ok "Doctor completed."
      ;;
    plan)
      preflight_common "$AUTO_FIX"
      apt_simulate_with_temp_sources
      ;;
    convert)
      convert_apply
      ;;
    rollback)
      rollback_apply "$ROLLBACK_DIR"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
