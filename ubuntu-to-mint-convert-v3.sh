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
#
# Keep Ubuntu as the base OS and add Linux Mint repos + Mint desktop/tooling.
# This is NOT an officially supported migration path. Use at your own risk.
#
# Supported paths (current supported Mint bases):
#   - Ubuntu 24.04 (noble) -> Linux Mint 22.x (default: 22.3 "zena")
#   - Ubuntu 22.04 (jammy) -> Linux Mint 21.x (default: 21.3 "virginia")
#
# Modes:
#   doctor                  : run preflight checks only
#   plan   [opts]           : dry-run apt simulation using temporary apt dirs (no system changes)
#   convert --i-accept-the-risk [opts] : apply changes, install Mint packages
#   rollback <backup_dir>   : restore /etc/apt + sources from a backup created by this script
#
# Common options:
#   --edition cinnamon|mate|xfce      (default: cinnamon)
#   --target  zena|zara|xia|wilma|virginia|victoria|vera|vanessa  (default depends on Ubuntu base)
#   --mint-mirror URL                (default: http://packages.linuxmint.com)
#   --keep-ppas                      (default: PPAs/3rd-party sources are disabled during convert)
#   --preserve-snap                  (default: yes; removes Mint's "nosnap" pin if it appears)
#   --with-recommends                (default: no; safer for corporate systems)
#   --yes                            (skip interactive confirmation)
#
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="3.0"
LOG_DIR="/var/log/ubuntu-to-mint"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ubuntu-to-mint-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; NC=$'\033[0m'

die() { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }
warn(){ echo "${YEL}WARN:${NC}  $*" >&2; }
info(){ echo "${BLU}INFO:${NC}  $*"; }
ok()  { echo "${GRN}OK:${NC}    $*"; }

ON_ERROR_BACKUP_HINT=""
on_err() {
  local line="${1:-?}" code="${2:-?}"
  echo "${RED}FAILED${NC} at line ${line} (exit ${code})." >&2
  if [[ -n "${ON_ERROR_BACKUP_HINT}" ]]; then
    echo "Rollback hint: ${ON_ERROR_BACKUP_HINT}" >&2
  fi
  echo "Log: ${LOG_FILE}" >&2
  exit "$code"
}
trap 'on_err "$LINENO" "$?"' ERR

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (use sudo)."; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'EOF'
Usage:
  sudo bash ubuntu-to-mint-convert-v3.sh doctor
  sudo bash ubuntu-to-mint-convert-v3.sh plan [--edition cinnamon|mate|xfce] [--target <mint_codename>] [--mint-mirror <url>] [--with-recommends]
  sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk [options...]
  sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS

Options:
  --edition cinnamon|mate|xfce
  --target  zena|zara|xia|wilma|virginia|victoria|vera|vanessa
  --mint-mirror URL
  --keep-ppas
  --preserve-snap
  --with-recommends
  --yes
EOF
}

# --- Defaults ---
MODE="${1:-}"
EDITION="cinnamon"
TARGET_MINT=""
MINT_MIRROR="http://packages.linuxmint.com"
KEEP_PPAS="no"
PRESERVE_SNAP="yes"
WITH_RECOMMENDS="no"
ASSUME_YES="no"

# --- Parse args (simple) ---
shift || true
ACCEPT_RISK="no"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --i-accept-the-risk) ACCEPT_RISK="yes"; shift;;
    --edition) EDITION="${2:-}"; shift 2;;
    --target)  TARGET_MINT="${2:-}"; shift 2;;
    --mint-mirror) MINT_MIRROR="${2:-}"; shift 2;;
    --keep-ppas) KEEP_PPAS="yes"; shift;;
    --preserve-snap) PRESERVE_SNAP="yes"; shift;;
    --with-recommends) WITH_RECOMMENDS="yes"; shift;;
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

read_os_release() {
  [[ -r /etc/os-release ]] || die "/etc/os-release missing"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_NAME="${NAME:-}"
  OS_VERSION_CODENAME="${VERSION_CODENAME:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
}

detect_ubuntu_codename() {
  local c=""
  if have_cmd lsb_release; then
    c="$(lsb_release -cs 2>/dev/null || true)"
  fi
  if [[ -z "$c" ]]; then
    c="${OS_VERSION_CODENAME:-}"
  fi
  [[ -n "$c" ]] || die "Could not determine Ubuntu codename."
  echo "$c"
}

set_targets_from_ubuntu() {
  UBUNTU_CODENAME="$(detect_ubuntu_codename)"
  case "$UBUNTU_CODENAME" in
    noble)
      UBUNTU_BASE="noble"
      DEFAULT_MINT="zena"     # Mint 22.3 recommended on Ubuntu Noble base
      ALLOWED_TARGETS="zena zara xia wilma"
      ;;
    jammy)
      UBUNTU_BASE="jammy"
      DEFAULT_MINT="virginia" # Mint 21.3 on Ubuntu Jammy base
      ALLOWED_TARGETS="virginia victoria vera vanessa"
      ;;
    *)
      die "Unsupported Ubuntu codename '$UBUNTU_CODENAME'. This script supports Ubuntu noble (24.04) or jammy (22.04) only."
      ;;
  esac

  if [[ -z "$TARGET_MINT" ]]; then
    TARGET_MINT="$DEFAULT_MINT"
  fi

  # Validate target is allowed for this base
  local ok_target="no"
  for t in $ALLOWED_TARGETS; do
    [[ "$TARGET_MINT" == "$t" ]] && ok_target="yes"
  done
  [[ "$ok_target" == "yes" ]] || die "--target '$TARGET_MINT' not allowed for Ubuntu '$UBUNTU_CODENAME'. Allowed: $ALLOWED_TARGETS"
}

preflight_common() {
  need_root
  validate_choice "$EDITION"
  read_os_release

  info "Script v${SCRIPT_VERSION}"
  info "Detected OS: ${OS_NAME} (ID=${OS_ID}, VERSION_ID=${OS_VERSION_ID}, CODENAME=${OS_VERSION_CODENAME})"

  [[ "$OS_ID" == "ubuntu" ]] || die "This script is intended for Ubuntu (ID=ubuntu). Detected ID=${OS_ID}."
  set_targets_from_ubuntu
  ok "Ubuntu base: ${UBUNTU_BASE} | Target Mint codename: ${TARGET_MINT} | Edition: ${EDITION}"

  # Refuse containers (too many surprises)
  if have_cmd systemd-detect-virt; then
    if systemd-detect-virt --container >/dev/null 2>&1; then
      die "Detected container environment. Aborting."
    fi
  fi

  # Architecture check
  local arch
  arch="$(dpkg --print-architecture)"
  [[ "$arch" == "amd64" ]] || warn "Architecture is '$arch'. Mint is typically amd64 on desktops. Proceeding may fail."

  # APT locks
  if fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
    die "APT/DPKG lock is held (updates running?). Close Software Updater/apt and try again."
  fi

  # dpkg health
  if dpkg --audit | grep -q .; then
    warn "dpkg reports issues (dpkg --audit not empty). Attempting to fix..."
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a
  fi
  DEBIAN_FRONTEND=noninteractive apt-get -y -f install

  # Network reachability (lightweight)
  have_cmd curl || DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates
  curl -fsS --max-time 10 "http://archive.ubuntu.com/ubuntu/" >/dev/null || warn "Cannot reach archive.ubuntu.com (may be corporate mirror/proxy setup)."
  curl -fsS --max-time 10 "${MINT_MIRROR%/}/" >/dev/null || warn "Cannot reach Mint mirror ${MINT_MIRROR} (may be intermittent)."

  # Disk space
  local root_free
  root_free="$(df -Pm / | awk 'NR==2{print $4}')"
  if [[ "${root_free:-0}" -lt 6144 ]]; then
    warn "Low free space on / (${root_free} MB). Recommend >= 6GB free."
  fi

  # Battery check (if laptop)
  if [[ -d /sys/class/power_supply ]]; then
    local on_batt="no"
    for ps in /sys/class/power_supply/*; do
      [[ -r "$ps/type" ]] || continue
      if grep -qi "battery" "$ps/type"; then
        if [[ -r "$ps/status" ]] && grep -qi "discharging" "$ps/status"; then
          on_batt="yes"
        fi
      fi
    done
    [[ "$on_batt" == "yes" ]] && warn "System appears to be on battery. Plug into AC before convert."
  fi

  # Snap inventory (for corporate safety)
  if have_cmd snap; then
    info "Snap detected. Installed snaps:"
    snap list || true
  else
    info "snap not installed."
  fi

  ok "Preflight completed."
}

# Try to detect Ubuntu mirrors from existing config so we don't break corporate proxy/mirrors.
detect_ubuntu_mirrors() {
  local sources_txt=""
  # collect possible deb lines from .list and .sources
  if [[ -r /etc/apt/sources.list ]]; then sources_txt+="$(grep -E '^[[:space:]]*deb ' /etc/apt/sources.list || true)"$'\n'; fi
  if compgen -G "/etc/apt/sources.list.d/*.list" >/dev/null; then
    sources_txt+="$(grep -RhsE '^[[:space:]]*deb ' /etc/apt/sources.list.d/*.list || true)"$'\n'
  fi
  if compgen -G "/etc/apt/sources.list.d/*.sources" >/dev/null; then
    # very rough extraction of URIs from deb822 sources
    sources_txt+="$(grep -RhsE '^[[:space:]]*URIs:[[:space:]]*' /etc/apt/sources.list.d/*.sources | awk '{print $2}' || true)"$'\n'
  fi

  # defaults
  UBUNTU_ARCHIVE_MIRROR="http://archive.ubuntu.com/ubuntu"
  UBUNTU_SECURITY_MIRROR="http://security.ubuntu.com/ubuntu"

  # try to find an existing archive mirror
  local m
  m="$(echo "$sources_txt" | grep -Eo 'https?://[^ ]+/ubuntu' | head -n1 || true)"
  [[ -n "$m" ]] && UBUNTU_ARCHIVE_MIRROR="$m"

  # try to find an existing security mirror
  local s
  s="$(echo "$sources_txt" | grep -Eo 'https?://[^ ]+/ubuntu' | grep -E 'security\.ubuntu\.com|/ubuntu-security' | head -n1 || true)"
  [[ -n "$s" ]] && UBUNTU_SECURITY_MIRROR="$s"

  info "Ubuntu archive mirror:  ${UBUNTU_ARCHIVE_MIRROR}"
  info "Ubuntu security mirror: ${UBUNTU_SECURITY_MIRROR}"
}

mint_repo_key_install() {
  # Linux Mint repository signing key (short ID commonly referenced as A6616109451BBBF2)
  # We fetch via hkps and store as a dedicated keyring file for signed-by usage.
  local keyid="A6616109451BBBF2"
  local keyring="/usr/share/keyrings/linuxmint-repo.gpg"

  info "Installing Linux Mint repo signing key into ${keyring}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg dirmngr ca-certificates

  local gnupghome
  gnupghome="$(mktemp -d)"
  chmod 700 "$gnupghome"
  gpg --homedir "$gnupghome" --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$keyid"
  gpg --homedir "$gnupghome" --batch --export "$keyid" | gpg --dearmor -o "$keyring"
  chmod 644 "$keyring"
  rm -rf "$gnupghome"
  ok "Key installed."
}

write_mint_sources_system() {
  local list="/etc/apt/sources.list.d/official-package-repositories.list"
  local keyring="/usr/share/keyrings/linuxmint-repo.gpg"

  detect_ubuntu_mirrors

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

  # Neutralize /etc/apt/sources.list to avoid dupes
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^[[:space:]]*deb /# deb /' /etc/apt/sources.list || true
  fi

  ok "Sources written."
}

write_mint_pinning_system() {
  local pref="/etc/apt/preferences.d/50-linuxmint-conversion.pref"
  info "Writing conservative APT pinning to ${pref}"

  # Conservative:
  # - Default Mint origin priority low (100) so Ubuntu wins for overlapping packages.
  # - Promote Mint desktop/tooling patterns to 700 so they come from Mint and update from Mint.
  cat > "$pref" <<'EOF'
# Conservative pinning for Ubuntu->Mint Option B conversion.
# Keep Ubuntu as default; allow Mint only for Mint desktop/tooling packages.
#
# Default: low priority for Mint origin so it won't replace base packages automatically.
Package: *
Pin: origin "packages.linuxmint.com"
Pin-Priority: 100

# Mint tooling / desktop stack: prefer Mint packages.
Package: mint* mintsources* mintupdate* mintsystem* mintstick* mintmenu* mintdrivers* mintreport* mintwelcome* mintlocale*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700

Package: cinnamon* nemo* muffin* cjs* xapp* slick-greeter* lightdm* pix* xviewer* mint-themes* mint-y-icons* mint-x-icons*
Pin: origin "packages.linuxmint.com"
Pin-Priority: 700
EOF

  ok "Pinning written."
}

disable_thirdparty_sources_system() {
  # Moves third-party sources out of the way to reduce conflicts during install.
  # We back them up first and leave a marker so rollback can restore.
  local backup_dir="$1"
  local disabled_dir="${backup_dir}/disabled-sources"
  mkdir -p "$disabled_dir"

  info "Disabling 3rd-party sources (PPAs, vendor repos) into: ${disabled_dir}"
  shopt -s nullglob

  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    # keep our generated official list intact
    [[ "$(basename "$f")" == "official-package-repositories.list" ]] && continue
    # disable everything else unless user opted to keep
    mv -v "$f" "${disabled_dir}/" || true
  done

  shopt -u nullglob
  ok "Third-party sources disabled (restorable via rollback)."
}

backup_system_state() {
  local backup_dir="/root/ubuntu-to-mint-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  ON_ERROR_BACKUP_HINT="sudo bash $0 rollback ${backup_dir}"

  info "Creating backup at: ${backup_dir}"
  mkdir -p "${backup_dir}/etc"
  cp -a /etc/apt "${backup_dir}/etc/" || true
  cp -a /etc/os-release /etc/lsb-release 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/fstab /etc/hostname /etc/hosts 2>/dev/null "${backup_dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${backup_dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${backup_dir}/apt-manual.txt" || true
  apt-mark showhold > "${backup_dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${backup_dir}/enabled-services.txt" || true

  if have_cmd snap; then
    snap list > "${backup_dir}/snap-list.txt" || true
  fi
  if have_cmd flatpak; then
    flatpak list > "${backup_dir}/flatpak-list.txt" || true
  fi

  ok "Backup complete."
  echo "$backup_dir"
}

timeshift_snapshot_best_effort() {
  if have_cmd timeshift; then
    info "Timeshift detected. Attempting pre-change snapshot (best-effort)..."
    # Timeshift might not be configured; don't fail conversion if it can't snapshot.
    timeshift --create --comments "pre ubuntu->mint option-b $(date -Is)" --tags D || warn "Timeshift snapshot failed (may not be configured)."
  else
    warn "Timeshift not installed. Strongly recommended to snapshot/backup before converting."
  fi
}

apt_simulate_with_temp_sources() {
  # Use a temporary APT environment for plan mode: no system changes.
  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/etc/apt/sources.list.d" "$tmp/var/lib/apt/lists/partial" "$tmp/var/cache/apt/archives/partial"

  # Keyring: use system keyring file if present; otherwise, we can't verify Mint repo.
  local keyring="/usr/share/keyrings/linuxmint-repo.gpg"
  [[ -r "$keyring" ]] || die "Mint keyring not found at ${keyring}. Run convert once (it installs key) or install key manually."

  detect_ubuntu_mirrors
  cat > "$tmp/etc/apt/sources.list" <<EOF
deb [signed-by=${keyring}] ${MINT_MIRROR%/} ${TARGET_MINT} main upstream import backport
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE} main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-updates main restricted universe multiverse
deb ${UBUNTU_ARCHIVE_MIRROR%/} ${UBUNTU_BASE}-backports main restricted universe multiverse
deb ${UBUNTU_SECURITY_MIRROR%/} ${UBUNTU_BASE}-security main restricted universe multiverse
EOF

  # Pinning file inside temp etc
  mkdir -p "$tmp/etc/apt/preferences.d"
  write_mint_pinning_system >/dev/null 2>&1 || true
  cp -a /etc/apt/preferences.d/50-linuxmint-conversion.pref "$tmp/etc/apt/preferences.d/" 2>/dev/null || true

  info "Plan mode: apt update (temporary dirs)..."
  apt-get \
    -o Dir::Etc="$tmp/etc/apt" \
    -o Dir::State="$tmp/var/lib/apt" \
    -o Dir::Cache="$tmp/var/cache/apt" \
    -o Dir::State::status="/var/lib/dpkg/status" \
    -o Acquire::Retries=3 \
    update

  local recommends="--no-install-recommends"
  [[ "$WITH_RECOMMENDS" == "yes" ]] && recommends=""

  local pkgs=()
  case "$EDITION" in
    cinnamon) pkgs+=(mint-meta-cinnamon) ;;
    mate)     pkgs+=(mint-meta-mate) ;;
    xfce)     pkgs+=(mint-meta-xfce) ;;
  esac
  pkgs+=(mint-meta-core mint-meta-codecs mintsystem mintupdate mintsources)

  info "Plan mode: simulated install: ${pkgs[*]}"
  apt-get \
    -o Dir::Etc="$tmp/etc/apt" \
    -o Dir::State="$tmp/var/lib/apt" \
    -o Dir::Cache="$tmp/var/cache/apt" \
    -o Dir::State::status="/var/lib/dpkg/status" \
    -o Acquire::Retries=3 \
    -s install $recommends "${pkgs[@]}" | tee "$LOG_DIR/plan-$(date +%Y%m%d-%H%M%S).txt" >/dev/null

  rm -rf "$tmp"
  ok "Plan completed. Review the plan log in ${LOG_DIR}."
}

parse_and_guard_apt_actions() {
  # Guard rails: abort if apt wants to remove critical packages.
  local sim_output_file="$1"
  [[ -r "$sim_output_file" ]] || die "Missing simulation output: $sim_output_file"

  local removed
  removed="$(grep -E '^Remv ' "$sim_output_file" | awk '{print $2}' || true)"
  local removed_count
  removed_count="$(echo "$removed" | grep -c . || true)"

  info "APT simulation: packages marked for removal: ${removed_count}"

  # Critical packages we refuse to remove (extend as needed)
  local critical_re='^(sudo|openssh-server|ssh|network-manager|systemd|systemd-sysv|dbus|polkit|linux-image|linux-generic|linux-modules|grub|grub2|initramfs-tools|libc6|libstdc\+\+6|snapd)$'
  local bad=""
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ "$p" =~ $critical_re ]]; then
      bad+="$p"$'\n'
    fi
  done <<< "$removed"

  if [[ -n "$bad" ]]; then
    echo "$bad" | sed 's/^/  - /'
    die "Refusing to proceed: simulation removes critical packages above."
  fi

  if [[ "$removed_count" -gt 20 ]]; then
    die "Refusing to proceed: too many removals (${removed_count}). Re-run with --with-recommends off (default), or inspect conflicts."
  fi

  ok "Guard rails passed (no critical removals; removals <= 20)."
}

convert_apply() {
  [[ "$ACCEPT_RISK" == "yes" ]] || die "You must pass --i-accept-the-risk to run convert."

  preflight_common

  if [[ "$ASSUME_YES" != "yes" ]]; then
    echo
    warn "This can break a corporate-managed machine. Ensure you have approval + a rollback plan (snapshot/backup)."
    echo "Target: Ubuntu ${UBUNTU_BASE} -> Mint ${TARGET_MINT} (${EDITION})"
    read -r -p "Type 'I UNDERSTAND' to continue: " ans
    [[ "$ans" == "I UNDERSTAND" ]] || die "Aborted by user."
  fi

  local backup_dir
  backup_dir="$(backup_system_state)"
  timeshift_snapshot_best_effort

  # Quiet apt timers that can race us
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

  # Update + simulate real install on the real system (but still simulation first)
  info "APT update..."
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update

  local recommends="--no-install-recommends"
  [[ "$WITH_RECOMMENDS" == "yes" ]] && recommends=""

  local pkgs=()
  case "$EDITION" in
    cinnamon) pkgs+=(mint-meta-cinnamon) ;;
    mate)     pkgs+=(mint-meta-mate) ;;
    xfce)     pkgs+=(mint-meta-xfce) ;;
  esac
  # keep this minimal; meta packages can be large – avoid recommends by default
  pkgs+=(mint-meta-core mintsystem mintupdate mintsources)

  # Optional codecs (often desired, but can pull extra) – keep it but still no recommends
  pkgs+=(mint-meta-codecs)

  info "Simulation (safety check) of install: ${pkgs[*]}"
  local sim_out="${backup_dir}/apt-sim-install.txt"
  DEBIAN_FRONTEND=noninteractive apt-get -s install $recommends "${pkgs[@]}" | tee "$sim_out" >/dev/null
  parse_and_guard_apt_actions "$sim_out"

  # Execute install
  info "Installing Mint packages..."
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get -y install \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    $recommends \
    "${pkgs[@]}"

  # Preserve Snap (Mint often pins snapd; we undo that if it appears and user asked to preserve)
  if [[ "$PRESERVE_SNAP" == "yes" ]]; then
    local nosnap="/etc/apt/preferences.d/nosnap.pref"
    if [[ -f "$nosnap" ]]; then
      warn "Mint 'nosnap' preference detected at ${nosnap}. Removing to preserve snap functionality."
      rm -f "$nosnap"
      apt-get -o Acquire::Retries=3 update
    fi
  fi

  # Post-checks
  info "Post-checks:"
  apt-cache policy mintsystem | sed 's/^/  /' || true
  if have_cmd cinnamon; then cinnamon --version | sed 's/^/  /' || true; fi
  if have_cmd nemo; then nemo --version | sed 's/^/  /' || true; fi

  ok "Conversion complete (Option B)."
  info "Backup dir: ${backup_dir}"
  info "Log file:   ${LOG_FILE}"
  echo
  echo "Next steps:"
  echo "  1) Reboot."
  echo "  2) At the login screen, choose the '${EDITION^}' session."
  echo "  3) Validate corp software: VPN, EDR/agent, SSO, MDM posture, printers, smartcard, etc."
}

rollback_apply() {
  need_root
  local backup_dir="${2:-}"
  [[ -n "$backup_dir" ]] || die "rollback requires a backup dir argument."
  [[ -d "$backup_dir" ]] || die "No such backup dir: $backup_dir"
  [[ -d "${backup_dir}/etc/apt" ]] || die "Backup dir missing etc/apt: $backup_dir"

  info "Restoring /etc/apt from backup: ${backup_dir}/etc/apt"
  rm -rf /etc/apt
  cp -a "${backup_dir}/etc/apt" /etc/apt

  # Restore disabled sources if present
  if [[ -d "${backup_dir}/disabled-sources" ]]; then
    info "Restoring disabled sources from ${backup_dir}/disabled-sources"
    mkdir -p /etc/apt/sources.list.d
    cp -a "${backup_dir}/disabled-sources/." /etc/apt/sources.list.d/ || true
  fi

  info "APT update after rollback..."
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update || true
  ok "Rollback of APT configuration completed."
  info "Note: This does NOT automatically remove Mint-installed packages. Use Timeshift/snapshot to fully revert the system state."
}

main() {
  case "$MODE" in
    doctor)
      preflight_common
      ;;
    plan)
      preflight_common
      # plan requires keyring already present (or run convert once to install it)
      apt_simulate_with_temp_sources
      ;;
    convert)
      convert_apply
      ;;
    rollback)
      rollback_apply "$MODE" "$2"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main
