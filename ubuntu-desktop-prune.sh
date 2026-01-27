#!/usr/bin/env bash
# ubuntu-desktop-prune.sh
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
SCRIPT_VERSION="1.1"

# =========================
# Globals / Defaults
# =========================
LOG_DIR="/var/log/ubuntu-to-mint"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/ubuntu-desktop-prune-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

CMD=""
ASSUME_YES="no"
WITH_RECOMMENDS="no"
SKIP_DM_FIX="no"
ROLLBACK_DIR=""

# For safety gates
MAX_REMOVALS_DEFAULT=75

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
die()  { echo "${RED}ERROR:${RESET} $*"; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "This must be run as root. Use: sudo bash $0 ..."
  fi
}

on_err() {
  local rc=$?
  local line="${BASH_LINENO[0]:-unknown}"
  echo "ERROR: FAILED at line ${line} (exit ${rc})."
  echo "ERROR: Command: ${BASH_COMMAND}"
  echo "ERROR: Log: ${LOG_FILE}"
  exit "$rc"
}
trap on_err ERR

usage() {
  cat <<EOF
ubuntu-desktop-prune.sh (v${SCRIPT_VERSION})

Goal:
  Best-effort, "gentle" removal of Ubuntu GNOME/Ubuntu-session desktop components
  AFTER you have a working non-Ubuntu desktop (e.g., Mint Cinnamon/MATE/Xfce).

Commands:
  sudo bash $0 doctor
  sudo bash $0 plan
  sudo bash $0 prune --yes
  sudo bash $0 rollback /root/ubuntu-desktop-prune-backup-YYYYMMDD-HHMMSS

Options:
  --yes              Non-interactive / proceed (required for prune)
  --with-recommends  Allow recommends (default: off)
  --skip-dm-fix      Do not attempt to set LightDM as default before pruning
EOF
}

# =========================
# APT sanity
# =========================
ensure_no_apt_locks() {
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
  for l in "${locks[@]}"; do
    if fuser "$l" >/dev/null 2>&1; then
      die "APT/dpkg lock is held (lock file: $l). Close package managers and try again."
    fi
  done
}

apt_fix_broken() {
  info "Attempting basic dpkg/apt remediation (best-effort)..."
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
  DEBIAN_FRONTEND=noninteractive apt-get -y -f install || true
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
# OS / environment checks
# =========================
detect_os_minimal() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  info "Script v${SCRIPT_VERSION}"
  info "Log: ${LOG_FILE}"
  info "Detected OS: ${NAME:-unknown} (ID=${ID:-?}, VERSION_ID=${VERSION_ID:-?}, CODENAME=${VERSION_CODENAME:-?})"

  # We allow Ubuntu base systems (including “Ubuntu-with-Mint-repos” setups).
  if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "linuxmint" ]]; then
    warn "OS ID is not ubuntu/linuxmint. Proceeding anyway, but this script is designed for Ubuntu base systems."
  fi

  if ! have_cmd apt-get || ! have_cmd dpkg; then
    die "apt-get/dpkg not found. This script requires Debian/Ubuntu-style package management."
  fi
}

# =========================
# Backup / rollback (limited)
# =========================
backup_state() {
  local backup_dir="/root/ubuntu-desktop-prune-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"

  info "Creating backup at: ${backup_dir}"
  mkdir -p "${backup_dir}/etc"
  cp -a /etc/apt "${backup_dir}/etc/" || true
  cp -a /etc/lightdm 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/X11/default-display-manager 2>/dev/null "${backup_dir}/etc/" || true
  cp -a /etc/systemd/system/display-manager.service 2>/dev/null "${backup_dir}/etc/" || true

  dpkg-query -W -f='${Package}\t${Version}\n' > "${backup_dir}/dpkg-packages.tsv" || true
  apt-mark showmanual > "${backup_dir}/apt-manual.txt" || true
  apt-mark showhold > "${backup_dir}/apt-holds.txt" || true
  systemctl list-unit-files --state=enabled > "${backup_dir}/enabled-services.txt" 2>/dev/null || true

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

  if [[ -d "$dir/etc/lightdm" ]]; then
    info "Restoring /etc/lightdm from backup..."
    rm -rf /etc/lightdm
    cp -a "$dir/etc/lightdm" /etc/lightdm
  fi

  if [[ -f "$dir/etc/default-display-manager" ]]; then
    info "Restoring /etc/X11/default-display-manager from backup..."
    mkdir -p /etc/X11
    cp -a "$dir/etc/default-display-manager" /etc/X11/default-display-manager
  fi

  if [[ -f "$dir/etc/display-manager.service" ]]; then
    info "Restoring /etc/systemd/system/display-manager.service from backup..."
    mkdir -p /etc/systemd/system
    cp -a "$dir/etc/display-manager.service" /etc/systemd/system/display-manager.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  ok "Rollback completed (APT + DM configs)."
  warn "Rollback does NOT automatically reinstall removed packages."
  info "Now run:"
  echo "  sudo apt-get update"
  echo "  sudo apt-get -f install"
}

# =========================
# Display manager hardening (noninteractive-safe)
# =========================
ensure_lightdm_default_noninteractive() {
  if [[ "$SKIP_DM_FIX" == "yes" ]]; then
    warn "--skip-dm-fix set; skipping LightDM default selection."
    return 0
  fi

  if [[ ! -d /run/systemd/system ]]; then
    warn "systemd not detected; skipping LightDM enablement."
    return 0
  fi

  info "Ensuring LightDM is default display manager (debconf preseed + dpkg-reconfigure)..."

  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) install lightdm slick-greeter debconf-utils >/dev/null 2>&1 || true

  # Preseed the DM selection so noninteractive installs switch away from gdm3.
  # Key: shared/default-x-display-manager
  echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections || true

  # Apply selection
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive lightdm >/dev/null 2>&1 || true

  # Debian/Ubuntu mechanism
  mkdir -p /etc/X11
  echo "/usr/sbin/lightdm" > /etc/X11/default-display-manager || true

  if have_cmd update-alternatives; then
    update-alternatives --set x-display-manager /usr/sbin/lightdm >/dev/null 2>&1 || true
  fi

  # If gdm3 exists, disable it so it can't take control
  if systemctl list-unit-files | awk '{print $1}' | grep -qx 'gdm3.service'; then
    systemctl disable --now gdm3 >/dev/null 2>&1 || true
    systemctl mask gdm3 >/dev/null 2>&1 || true
  fi

  # Ensure LightDM enabled
  systemctl unmask lightdm >/dev/null 2>&1 || true
  systemctl set-default graphical.target >/dev/null 2>&1 || true
  systemctl enable lightdm >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  # Best-effort start
  systemctl restart lightdm >/dev/null 2>&1 || true

  ok "LightDM default selection/enablement applied."
}

# =========================
# Target selection
# =========================
pkg_installed() {
  dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -q "install ok installed"
}

build_prune_list() {
  # Conservative list: remove Ubuntu GNOME session + Ubuntu desktop meta packages + GDM.
  # We intentionally avoid removing libs/toolkit packages that Cinnamon/Xfce/MATE may still rely on.
  local -a candidates=(
    ubuntu-desktop
    ubuntu-desktop-minimal
    ubuntu-session
    ubuntu-session-minimal
    gdm3
    gnome-shell
    gnome-shell-common
    gnome-shell-extension-ubuntu-dock
    yaru-theme-gnome
    yaru-theme-gtk
    yaru-theme-icon
    yaru-theme-sound
    ubuntu-wallpapers
    ubuntu-wallpapers-noble
    ubuntu-wallpapers-jammy
    gnome-software
    snap-store
  )

  local -a selected=()
  local p
  for p in "${candidates[@]}"; do
    if pkg_installed "$p"; then
      selected+=("$p")
    fi
  done

  printf '%s\n' "${selected[@]}"
}

show_target_summary() {
  local -a pkgs=("$@")
  if [[ ${#pkgs[@]} -eq 0 ]]; then
    warn "No target packages from the conservative prune list are currently installed."
    warn "Nothing to do."
    return 1
  fi

  info "Prune targets (installed):"
  printf '  - %s\n' "${pkgs[@]}"
  return 0
}

# =========================
# Simulation + safety gates
# (FIXED: exact-match critical package detection)
# =========================
apt_simulate_purge() {
  local -a pkgs=("$@")
  local sim="/tmp/ubuntu-desktop-prune-sim.$$.txt"

  info "Simulating purge (no changes)..."
  set +e
  DEBIAN_FRONTEND=noninteractive apt-get -s purge --autoremove "${pkgs[@]}" 2>&1 | tee "$sim"
  local rc=${PIPESTATUS[0]}
  set -e

  [[ $rc -eq 0 ]] || die "APT simulation failed (exit $rc). See: $sim"

  # Build an exact package list from the simulation.
  # APT prints: "Remv <pkg>:amd64 ..." or "Purg <pkg> ..."
  mapfile -t sim_removed < <(
    awk '/^(Remv|Purg)[[:space:]]+/{print $2}' "$sim" \
      | sed -E 's/:[a-z0-9]+$//' \
      | sort -u
  )

  # Hard stops: ONLY if these exact packages are removed.
  # NOTE: do NOT treat "systemd-*" as a hard stop.
  local -a critical_exact=(
    sudo
    systemd
    systemd-sysv
    network-manager
    openssh-server
    linux-image-generic
    linux-image-amd64
  )

  local c r
  for c in "${critical_exact[@]}"; do
    for r in "${sim_removed[@]}"; do
      if [[ "$r" == "$c" ]]; then
        die "Simulation shows removal of critical package '${c}'. Aborting. See: $sim"
      fi
    done
  done

  local remv_count
  remv_count="$(grep -cE '^(Remv|Purg)[[:space:]]' "$sim" || true)"
  info "Simulation removal count: ${remv_count}"

  if [[ "${ASSUME_YES}" != "yes" && "${remv_count}" -gt "${MAX_REMOVALS_DEFAULT}" ]]; then
    die "Simulation wants to remove ${remv_count} packages (too many for 'gentle'). Re-run with --yes only if you reviewed $sim."
  fi

  ok "Simulation looks acceptable. Review: $sim"
}

# =========================
# Commands
# =========================
doctor() {
  need_root
  ensure_no_apt_locks
  detect_os_minimal

  info "Doctor checks..."
  apt_fix_broken

  local holds
  holds="$(apt-mark showhold || true)"
  if [[ -n "$holds" ]]; then
    warn "Held packages detected (may affect pruning):"
    echo "$holds"
  else
    ok "No held packages detected."
  fi

  local -a pkgs=()
  mapfile -t pkgs < <(build_prune_list || true)

  if show_target_summary "${pkgs[@]}"; then
    ok "Doctor complete."
  else
    ok "Doctor complete (nothing obvious to prune)."
  fi
}

plan() {
  need_root
  ensure_no_apt_locks
  detect_os_minimal
  apt_fix_broken

  local -a pkgs=()
  mapfile -t pkgs < <(build_prune_list || true)
  show_target_summary "${pkgs[@]}" || return 0

  # LightDM check (plan-time warning)
  if [[ "$SKIP_DM_FIX" != "yes" ]]; then
    if ! pkg_installed lightdm; then
      warn "lightdm is not installed. prune will attempt to install/activate it first."
    fi
    if [[ -f /etc/X11/default-display-manager ]]; then
      info "Current default-display-manager: $(cat /etc/X11/default-display-manager || true)"
    fi
  fi

  apt_simulate_purge "${pkgs[@]}"
}

prune() {
  need_root
  ensure_no_apt_locks
  detect_os_minimal

  if [[ "$ASSUME_YES" != "yes" ]]; then
    die "prune is destructive and requires --yes"
  fi

  apt_fix_broken

  local -a pkgs=()
  mapfile -t pkgs < <(build_prune_list || true)
  show_target_summary "${pkgs[@]}" || return 0

  # Ensure DM is safe before removing gdm3/gnome session packages
  ensure_lightdm_default_noninteractive

  # Re-run simulation immediately before changes
  apt_simulate_purge "${pkgs[@]}"

  local backup_dir
  backup_dir="$(backup_state)"
  info "Backup dir: ${backup_dir}"

  info "Proceeding with purge..."
  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) purge --autoremove "${pkgs[@]}"

  info "Post-purge remediation..."
  apt_fix_broken
  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) autoremove --purge || true
  DEBIAN_FRONTEND=noninteractive apt-get $(apt_opts_common) clean || true

  ok "Prune completed."
  info "Log: ${LOG_FILE}"
  info "Backup (limited): ${backup_dir}"
  info "Next:"
  echo "  1) Reboot"
  echo "  2) Confirm you can login to your desired session"
  echo "  3) If you hit issues, restore via Timeshift/snapshot (preferred) or rollback APT/DM configs:"
  echo "     sudo bash $0 rollback ${backup_dir}"
}

# =========================
# Arg parsing (command-first OR options-first)
# =========================
parse_args_any_order() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      doctor|plan|prune|rollback)
        [[ -z "$CMD" ]] || die "Multiple commands specified: '${CMD}' and '$1'"
        CMD="$1"
        shift 1
        if [[ "$CMD" == "rollback" ]]; then
          if [[ $# -gt 0 && "${1:-}" != --* ]]; then
            ROLLBACK_DIR="$1"
            shift 1
          fi
        fi
        ;;
      --yes) ASSUME_YES="yes"; shift 1;;
      --with-recommends) WITH_RECOMMENDS="yes"; shift 1;;
      --skip-dm-fix) SKIP_DM_FIX="yes"; shift 1;;
      -h|--help|help) usage; exit 0;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

main() {
  parse_args_any_order "$@"
  [[ -n "$CMD" ]] || { usage; exit 1; }

  case "$CMD" in
    doctor) doctor ;;
    plan) plan ;;
    prune) prune ;;
    rollback)
      [[ -n "$ROLLBACK_DIR" ]] || die "rollback requires a directory argument"
      rollback "$ROLLBACK_DIR"
      ;;
    *) die "Unknown command: $CMD" ;;
  esac
}

main "$@"
