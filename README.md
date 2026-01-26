# ubuntu2mint / ubuntu-to-mint-convert-v3

High-risk, best-effort **in-place conversion** script that keeps **Ubuntu as the base OS** while adding **Linux Mint repositories + Mint desktop/tooling** to approximate a Linux Mint system **without a full reinstall**.

This project is intended for experienced Linux admins who understand APT, repo pinning, display managers, and rollback strategies.

> 🟥 **UNSUPPORTED + PROBABLY DUMB (READ THIS FIRST)**  
> There is **no guaranteed safe** way to convert Ubuntu to Linux Mint in-place and preserve *all* corporate software/agents.  
> **EDR/MDM/VPN/compliance tooling may break** and require re-enrollment.  
> A **clean install** (or a second disk/VM test) is the recommended approach.  
>  
> The script enforces an interactive “I understand” gate during `convert` and also requires `--i-accept-the-risk`.



## What this does

- Detects supported Ubuntu bases:
  - **Ubuntu 24.04 (noble)** → targets **Linux Mint 22.x** (default **22.3 “zena”**)
  - **Ubuntu 22.04 (jammy)** → targets **Linux Mint 21.x** (default **21.3 “virginia”**)
- Adds the Linux Mint package repository (`packages.linuxmint.com`)
- Keeps Ubuntu repos for the underlying base system
- Installs Mint meta-packages (desktop + tooling) and configures:
  - **LightDM** as default display manager
  - **slick-greeter** as greeter
  - Default desktop session based on `--edition`
- Applies conservative APT pinning:
  - Ubuntu remains default for overlapping base packages
  - Mint desktop stack is pinned high to avoid mixed-version dependency breakage
- Includes guardrails:
  - APT/dpkg lock detection
  - best-effort dpkg/apt repair (`--no-auto-fix` to disable)
  - simulation plan + safety checks (removal thresholds + critical package protection)
  - disables third-party sources by default (with allowlist heuristics for common corp repos)
  - backup + rollback support
  - post-conversion validation report written into the backup directory

## What this does *not* do

- It does **not** replace your OS identity with Mint in a fully supported way.
- It does **not** guarantee your machine remains compliant in managed enterprise environments.
- It does **not** guarantee perfect package resolution—APT may still want to remove packages.
- Rollback restores `/etc/apt`, but may not remove packages installed during conversion (use snapshots/Timeshift for full reversion).
- This script is **LightDM-first**, which implies **X11 sessions**; it does not attempt to force Wayland.



## Requirements

- Ubuntu **24.04 (noble)** or **22.04 (jammy)**
- Root access (`sudo`)
- Working APT and dpkg state (the script can attempt basic remediation)
- Internet access to:
  - Ubuntu mirrors (or your corporate mirror)
  - `packages.linuxmint.com`
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

Plan mode uses a **temporary APT environment** (it does not modify your system’s APT sources).
It creates a **temporary Mint keyring** by downloading and extracting the `linuxmint-keyring` package.

> Plan mode is for decision support. It does not modify `/etc/apt` or install Mint repos onto your live system.

### 3) Run conversion

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon
```

You can skip the secondary interactive confirmation prompts with `--yes`:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk --edition cinnamon --yes
```

> The big red unsupported disclaimer gate is still required during `convert` even with `--yes`.

### 4) Reboot and validate

After conversion:

1. Reboot
2. Login via LightDM and confirm your chosen session loads
3. Validate:

   * VPN connectivity (GlobalProtect, etc.)
   * EDR/MDM agents + compliance posture (CrowdStrike Falcon, etc.)
   * corporate certificates / SSO
   * NetworkManager
   * printers
   * smartcards / YubiKey
   * camera/audio



## Usage

```text
sudo bash ubuntu-to-mint-convert-v3.sh doctor [--no-auto-fix]
sudo bash ubuntu-to-mint-convert-v3.sh plan [options]
sudo bash ubuntu-to-mint-convert-v3.sh convert --i-accept-the-risk [options]
sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS
```



## Options

### Desktop / targets

* `--edition cinnamon|mate|xfce`
  Desktop edition meta-package to install (default: `cinnamon`).

* `--target <mint_codename>`
  Override the Mint target codename. Allowed targets depend on your Ubuntu base:

  * Ubuntu `noble`: `zena`, `zara`, `xia`, `wilma`
  * Ubuntu `jammy`: `virginia`, `victoria`, `vera`, `vanessa`

* `--mint-mirror <url>`
  Override Mint mirror base URL (default: `http://packages.linuxmint.com`)

### Safety / APT behavior

* `--keep-ppas`
  Do not disable third-party APT sources (not recommended).
  **Default behavior** disables PPAs and most third-party repos during conversion and moves them into the backup folder.
  Some common enterprise repos may be automatically allowlisted.

* `--with-recommends`
  Allow installation of recommended packages (default: off for safety).

* `--max-removals N`
  Abort if APT simulation removes more than N packages (default: `40`).

* `--yes`
  Skip most interactive prompts.
  (Does **not** bypass the `convert` disclaimer gate or `--i-accept-the-risk` requirement.)

* `--no-auto-fix`
  Disable best-effort dpkg/apt repair pre-flight.

### Keyring handling

* `--overwrite-keyring`
  If `/usr/share/keyrings/linuxmint-repo.gpg` exists, overwrite it.

* `--recreate-keyring`
  Back up and delete the keyring then recreate it.

### Flavor / meta package conflict handling

* `--no-purge-flavor`
  Disable best-effort purging of conflicting Ubuntu flavor packages (e.g., `ubuntucinnamon-*`) that can cause session crashes/login loops.



## Safety model (important)

Guardrails included to reduce “brick your system” outcomes:

* Refuses to run unless on supported Ubuntu bases
* Detects and blocks active APT/dpkg locks
* Attempts to repair basic dpkg/apt broken states (unless `--no-auto-fix`)
* Disables PPAs by default during conversion (unless `--keep-ppas`)
* Runs an APT simulation and aborts if:

  * APT wants to remove critical packages (e.g., `sudo`, `systemd`, `network-manager`, kernel meta packages)
  * too many removals are detected (default threshold `40`)
* Creates a backup directory for rollback
* Post-conversion validation writes a report into the backup directory (always created)



## Logs and backups

### Logs

* Main log:

  * `/var/log/ubuntu-to-mint/ubuntu-to-mint-YYYYMMDD-HHMMSS.log`
* Plan logs:

  * `/var/log/ubuntu-to-mint/plan-YYYYMMDD-HHMMSS.txt`

### Backup directory

During `convert`, a backup directory is created, e.g.:

* `/root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS/`

Contains:

* `/etc/apt` backup
* package inventories (`apt-manual`, holds, dpkg list)
* enabled systemd services list
* snap/flatpak lists (if installed)
* disabled third-party sources (if disabled)
* **post-convert validation report**:

  * `post-convert-validation.txt`



## Rollback

Rollback restores `/etc/apt` and any disabled sources from the backup:

```bash
sudo bash ubuntu-to-mint-convert-v3.sh rollback /root/ubuntu-to-mint-backup-YYYYMMDD-HHMMSS
sudo apt-get update
sudo apt-get -f install
```

> Rollback restores APT configuration but may not remove packages installed during conversion.
> For full restoration use Timeshift / snapshot / backup.



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
  * user session logs: `~/.xsession-errors`
* Reinstall key desktop components:

  * `sudo apt-get install --reinstall lightdm slick-greeter cinnamon-session cinnamon-settings-daemon muffin`

### Key retrieval / keyserver issues

This version avoids keyservers by default. It prefers:

* a locally installed `linuxmint-keyring` package, or
* downloading the latest `linuxmint-keyring_*.deb` from the Mint mirror and extracting the keyring

If your existing keyring is corrupt:

* rerun with `--recreate-keyring` or `--overwrite-keyring`

### Known dpkg overwrite conflict (mintupdate)

Some environments will hit a file conflict between `mintupdate` and `software-properties-gtk`
over an icon file. The script installs the Mint stack with a guarded dpkg overwrite option
to prevent conversion from halting.

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
