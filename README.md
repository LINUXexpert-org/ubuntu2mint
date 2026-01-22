# ubuntu-to-mint-convert-v3

High-risk, best-effort **in-place conversion** script that keeps **Ubuntu as the base OS** while adding **Linux Mint repositories + Mint desktop/tooling** to approximate a Linux Mint system without a full reinstall.

This project is intended for experienced Linux admins who understand APT, repo pinning, and rollback strategies.

> ⚠️ **Warning (Read This First)**  
> There is **no guaranteed safe** way to convert Ubuntu to Linux Mint in-place and preserve *all* corporate software/agents.  
> EDR/MDM/VPN/compliance tooling may break and require re-enrollment. Use this only if you accept that risk.

## What this does

- Detects supported Ubuntu bases:
  - **Ubuntu 24.04 (noble)** → targets **Linux Mint 22.x** (default **22.3 “zena”**)
  - **Ubuntu 22.04 (jammy)** → targets **Linux Mint 21.x** (default **21.3 “virginia”**)
- Adds the Linux Mint package repository (`packages.linuxmint.com`)
- Keeps Ubuntu repos for the underlying base system
- Installs Mint meta-packages (desktop + tooling)
- Applies conservative APT pinning so Ubuntu remains the default for overlapping packages
- Includes safety checks, dry-run planning, and rollback support


## What this does *not* do

- It does **not** replace your OS identity with Mint in a fully supported way.
- It does **not** guarantee your machine remains compliant in managed enterprise environments.
- It does **not** guarantee perfect package resolution—APT may still want to remove packages.
- Rollback restores `/etc/apt`, but may not remove packages installed during conversion (use snapshots/Timeshift for full reversion).

## Requirements

- Ubuntu **24.04 (noble)** or **22.04 (jammy)**
- Root access (`sudo`)
- Working APT and dpkg state (the script attempts basic remediation)
- Internet access to:
  - Ubuntu mirrors (or your corporate mirror)
  - `packages.linuxmint.com`
- Recommended:
  - **Timeshift** snapshot configured
  - Full-disk backup or VM snapshot

## Quick start

### 1) Clone and run doctor checks

```bash
git clone https://github.com/<your-username>/ubuntu-to-mint-convert-v3.git
cd ubuntu-to-mint-convert-v3
sudo bash ubuntu-to-mint-convert-v3.sh doctor
````

### 2) (Optional) Run plan mode (dry-run)

Plan mode simulates the APT changes and writes a log under `/var/log/ubuntu-to-mint/`.

```bash
sudo bash ubuntu-to-mint-convert-v3.sh plan --edition cinnamon
```

> Note: plan mode expects the Mint repo keyring to exist. If you haven’t run `convert` before, install the key or run convert on a test machine first.

### 3) Run conversion

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon
```

You can skip interactive confirmation with `--yes`:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon --yes
```

### 4) Reboot and validate

After conversion:

1. Reboot
2. Select your chosen desktop session at login
3. Validate:

   * VPN connectivity
   * EDR/MDM agents + compliance posture
   * Corporate certificates / SSO
   * NetworkManager
   * Printers
   * Smartcards / YubiKey
   * Cameras/audio

## Usage

```text
sudo bash ubuntu-to-mint-convert-v3.sh doctor
sudo bash ubuntu-to-mint-convert-v3.sh plan [options]
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk [options]
sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS
```

### Options

* `--edition cinnamon|mate|xfce`
  Desktop edition meta-package to install (default: `cinnamon`).

* `--target <mint_codename>`
  Override the Mint target codename. Allowed targets depend on your Ubuntu base:

  * Ubuntu `noble`: `zena`, `zara`, `xia`, `wilma`
  * Ubuntu `jammy`: `virginia`, `victoria`, `vera`, `vanessa`

* `--mint-mirror <url>`
  Override Mint mirror base URL (default: `http://packages.linuxmint.com`)

* `--keep-ppas`
  Do not disable third-party APT sources (not recommended).

* `--preserve-snap`
  Keep Snap working even if Mint preferences attempt to disable it (default: enabled).

* `--with-recommends`
  Allow installation of recommended packages (default: off for safety).

* `--yes`
  Skip interactive confirmation prompt.


## Safety model (important)

The script includes guardrails to reduce “brick your system” outcomes:

* Refuses to run unless on supported Ubuntu bases
* Detects and blocks active APT/dpkg locks
* Attempts to repair basic dpkg/apt broken states
* Disables PPAs by default during conversion
* Runs an APT simulation and aborts if:

  * APT wants to remove critical packages (e.g., `sudo`, `systemd`, `network-manager`, kernel packages, `snapd`)
  * too many removals are detected
* Writes detailed logs and creates a backup folder for rollback


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
* snap/flatpak lists (if installed)
* simulation output


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
  * Mint mirror reachable
  * corporate proxy settings
* If needed:

  * rollback using the backup directory

### Desktop won’t start / login loop

* Boot to a TTY (`Ctrl+Alt+F3`)
* Inspect:

  * `/var/log/syslog`
  * `journalctl -b -p err`
* Consider switching display manager or reinstalling desktop meta packages:

  * `sudo apt-get install --reinstall lightdm slick-greeter`

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

```
