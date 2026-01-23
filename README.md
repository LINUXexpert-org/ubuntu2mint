# ubuntu-to-mint-convert-v3

High-risk, best-effort **in-place conversion** script that keeps **Ubuntu as the base OS** while adding **Linux Mint repositories + Mint desktop/tooling** to approximate a Linux Mint system without a full reinstall.

This project is intended for experienced Linux admins who understand APT, repo pinning, display managers, and rollback strategies.

> ⚠️ **Warning (Read This First)**  
> There is **no guaranteed safe** way to convert Ubuntu to Linux Mint in-place and preserve *all* corporate software/agents.  
> EDR/MDM/VPN/compliance tooling may break and require re-enrollment. Use this only if you accept that risk.



## What changed in the latest script (v4.3)

- **Convert-only “unsupported migration” disclaimer gate** (requires typing: `I UNDERSTAND THIS IS UNSUPPORTED`)
- Defaults to **LightDM + slick-greeter** and explicitly sets the **default desktop session**
- **X11 is the default session preference** (safer for conversions/corporate tooling)
- Added `--prefer-wayland` (best-effort only; may fall back to X11 with a warning)
- Improved Mint repo key handling:
  - `--overwrite-keyring` / `--recreate-keyring`
  - automatic detection/repair if the keyring exists but doesn’t contain the expected key
  - HKPS → HKP:80 → HTTPS fallback, with **atomic keyring writes**
- Improved plan mode: uses a temporary APT environment (no changes to system APT files)



## What this does

- Detects supported Ubuntu bases:
  - **Ubuntu 24.04 (noble)** → targets **Linux Mint 22.x** (default target: **zena**)
  - **Ubuntu 22.04 (jammy)** → targets **Linux Mint 21.x** (default target: **virginia**)
- Adds the Linux Mint package repository (`packages.linuxmint.com`)
- Keeps Ubuntu repos for the underlying base system
- Installs Mint meta-packages (desktop + tooling)
- Applies conservative APT pinning so Ubuntu remains the default for overlapping packages
- Includes safety checks, dry-run planning, and rollback support
- Sets **display manager + greeter + default session** based on `--edition`



## What this does *not* do

- It does **not** replace your OS identity with Mint in a fully supported way.
- It does **not** guarantee your machine remains compliant in managed enterprise environments.
- It does **not** guarantee perfect package resolution—APT may still want to remove packages.
- Rollback restores `/etc/apt`, but may not remove packages installed during conversion (use snapshots/Timeshift for full reversion).
- `--prefer-wayland` is **best-effort** and may fall back to X11 depending on what sessions are available and LightDM compatibility.



## Requirements

- Ubuntu **24.04 (noble)** or **22.04 (jammy)**
- Root access (`sudo`)
- Working APT and dpkg state (the script attempts basic remediation)
- Internet access to:
  - Ubuntu mirrors (or your corporate mirror)
  - `packages.linuxmint.com`
  - key retrieval endpoints (HKPS/HKP/HTTPS fallbacks)
- Recommended:
  - **Timeshift** snapshot configured
  - Full-disk backup or VM snapshot



## Quick start

### 1) Clone and run doctor checks

```bash
git clone https://github.com/LINUXexpert-org/ubuntu2mint.git
cd ubuntu2mint
sudo bash ubuntu-to-mint-convert-v3.sh doctor
````

### 2) (Optional) Run plan mode (dry-run)

Plan mode simulates the APT changes and writes a log under `/var/log/ubuntu-to-mint/`.

```bash
sudo bash ubuntu-to-mint-convert-v3.sh plan --edition cinnamon
```

Plan mode simulates APT changes using a **temporary APT environment** (it does not modify your system’s APT sources).
It will fetch the Linux Mint repository signing key into a **temporary keyring** for the simulation.

> Note: If `curl`/`gnupg`/`dirmngr` are missing, plan mode may require installing prerequisites if you run with `--auto-fix`.
> No repository files on your system are changed by plan mode.

### 3) Run conversion

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon
```

You can skip the secondary confirmation prompt with `--yes`:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon --yes
```

> The **big red unsupported disclaimer** is still required during `convert` even if `--yes` is set.

### 4) Reboot and validate

After conversion:

1. Reboot
2. Login via LightDM (slyck-greeter) and confirm your default session loads
3. Validate:

   * VPN connectivity (GlobalProtect, etc.)
   * EDR/MDM agents + compliance posture (CrowdStrike Falcon, etc.)
   * Corporate certificates / SSO
   * NetworkManager
   * Printers
   * Smartcards / YubiKey
   * Cameras/audio



## Usage

```text
sudo bash ubuntu-to-mint-convert-v3.sh doctor [--auto-fix]
sudo bash ubuntu-to-mint-convert-v3.sh plan [options]
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk [options]
sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS
```



## Options

### Core

* `--edition cinnamon|mate|xfce`
  Desktop edition meta-package to install (default: `cinnamon`).

* `--target <mint_codename>`
  Override the Mint target codename. Allowed targets depend on your Ubuntu base:

  * Ubuntu `noble`: `zena`, `zara`, `xia`, `wilma`
  * Ubuntu `jammy`: `virginia`, `victoria`, `vera`, `vanessa`

* `--mint-mirror <url>`
  Override Mint mirror base URL (default: `https://packages.linuxmint.com`).

### Safety / APT behavior

* `--keep-ppas`
  Do not disable third-party APT sources (not recommended).

* `--allow-unhold`
  Temporarily unhold held packages during conversion (risky; holds are re-applied later).

* `--with-recommends`
  Allow installation of recommended packages (default: off for safety).

* `--auto-fix`
  For `doctor`/`plan`: allow basic dpkg/apt remediation and install missing tool prerequisites.

* `--yes`
  Skip the secondary interactive confirmation prompt inside convert (does **not** bypass the main disclaimer gate).

### Snap handling

* `--preserve-snap` (default)
  Keep Snap working even if Mint preferences attempt to disable it.

* `--no-preserve-snap`
  Do not try to preserve Snap behavior.

### Keyring handling

* `--overwrite-keyring`
  Overwrite the Mint repo keyring if it exists.

* `--recreate-keyring`
  Back up the existing keyring and recreate it from scratch.

### Wayland / X11 behavior

* (default) **Prefers X11 session**
  Safer for conversions and enterprise desktop tooling.

* `--prefer-wayland`
  Best-effort attempt to prefer Wayland if it is **LightDM-compatible** (otherwise warns and falls back to X11).



## Safety model (important)

The script includes guardrails to reduce “brick your system” outcomes:

* Refuses to run unless on supported Ubuntu bases
* Detects and blocks active APT/dpkg locks
* Attempts to repair basic dpkg/apt broken states
* Disables PPAs by default during conversion (while attempting to preserve vendor repos for Falcon/GlobalProtect when identifiable)
* Runs an APT simulation and aborts if:

  * APT wants to remove critical packages (e.g., `sudo`, `systemd`, `network-manager`, kernel packages, `snapd`)
  * too many removals are detected
* Writes detailed logs and creates a backup folder for rollback
* Validates post-conversion basics (LightDM default, session file, NetworkManager, apt health, and best-effort checks for Falcon/GlobalProtect presence)



## Logs and backups

### Logs

* Main log file:

  * `/var/log/ubuntu-to-mint/ubuntu-to-mint-YYYYMMDD-HHMMSS.log`
* Plan output logs:

  * `/var/log/ubuntu-to-mint/plan-YYYYMMDD-HHMMSS.txt`

### Backup directory

During `convert`, a backup directory is created, for example:

* `/root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS/`

Contains:

* `/etc/apt` backup
* package inventories (`apt-manual`, holds, dpkg list)
* enabled systemd services list
* simulation output
* (if present) saved list of held packages (when `--allow-unhold` is used)
* (if used) disabled third-party sources captured for restore



## Rollback

Rollback restores `/etc/apt` and any disabled sources from the backup:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS
sudo apt-get update
sudo apt-get -f install
```

> Rollback restores APT configuration but may not remove packages installed during conversion.
> For full restoration use Timeshift / snapshot / backup.



## Recommended workflow (for best odds)

1. Test in a VM first (same Ubuntu version and similar package set)
2. Ensure **Timeshift** is configured and can restore
3. Run:

   * `doctor`
   * `plan` and review logs
4. Only then run `convert`
5. Reboot and validate corporate tooling



## Troubleshooting

### APT update fails after conversion

* Check:

  * `/etc/apt/sources.list.d/official-package-repositories.list`
  * Mint mirror reachability
  * corporate proxy settings
* If needed:

  * rollback using the backup directory

### Desktop won’t start / login loop

* Boot to a TTY (`Ctrl+Alt+F3`)
* Inspect:

  * `journalctl -b -p err`
* Consider reinstalling LightDM and the greeter:

```bash
sudo apt-get install --reinstall lightdm slick-greeter
```

### Keyserver blocked / key import fails

* The script attempts HKPS → HKP:80 → HTTPS fallback.
* If a keyring already exists and is broken, try:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --recreate-keyring
```

### Corporate VPN/EDR breaks

* Reinstall using corporate-provided packages
* Re-enroll if required
* Validate kernel modules, certificate stores, and PAM stack



## Security & compliance considerations

If this is a corporate-managed device:

* Get explicit approval before modifying base OS repositories
* Confirm your organization’s standard OS images and compliance requirements
* Expect that security tooling may detect drift and require remediation



## License

Copyright (C) 2026 LINUXexpert.org

This project is licensed under the **GNU General Public License v3.0**.
See the `LICENSE` file or the header in `ubuntu-to-mint-convert-v3.sh`.



## Disclaimer

This project is provided as-is. You assume all risk for system instability, data loss, or compliance impact. Always have a tested restore path before running.
