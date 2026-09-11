# UAG on Proxmox VE

Deploy Omnissa Unified Access Gateway (UAG) to Proxmox VE, driven entirely by
the Proxmox REST API and a single INI file — the same "one INI, one command"
shape Omnissa's own `uagdeploy.ps1` uses for its officially supported
platforms (vSphere, Nutanix, OpenStack, Azure, AWS, GCE, Hyper-V).

Proxmox is not an officially supported UAG platform. This works because the
UAG appliance's own first-boot script detects its platform by pattern-matching
`dmesg` output rather than anything cryptographically tied to real Nutanix
hardware — see the [blog posts](#background--how-this-works) for the full
story. Treat this as unsupported, homelab-grade tooling: no Omnissa support
ticket will cover it, and nothing here is guaranteed to keep working across
future UAG builds.

## What's in this repository, and what isn't

This repository contains only original tooling written against Proxmox's
public REST API and UAG's documented cloud-init `user-data` field interface.
It does **not** contain, and will never contain, any of Omnissa's own
`uagdeploy*.ps1` scripts or the shared `uagdeploy.psm1` module — those are
Omnissa's copyrighted software, shipped only to customers with a valid
Omnissa/VMware entitlement. `Get-UagUserData.ps1` in this repo *does* call a
number of that module's own exported functions (`ImportIni`,
`GetJSONSettings`, `ReadOsLoginUsername`, and several field validators)
through its public API, exactly the way Omnissa's own platform scripts do —
this is ordinary interoperability, not a copy of the module itself. You need
your own entitlement to obtain `uagdeploy.psm1` and place it alongside these
scripts; without it, nothing here will run.

| File | Purpose |
|---|---|
| `uagdeploypve.ps1` | Main entry point. One INI file in, one deployed UAG instance out. |
| `uagdeploypve.psm1` | Proxmox REST API back end (auth, template/clone, snippet delivery). Imported by `uagdeploypve.ps1`. |
| `New-UagPveTemplate.ps1` | One-time, per-cluster setup: imports the UAG QCOW2 and converts it into a Proxmox template. |
| `Get-UagUserData.ps1` | Builds the UAG cloud-init `user-data` payload from an INI file. Called by `uagdeploypve.ps1` as a child process. |
| `uag-pve-api-example.ini` | Fully-commented example INI — start here. |

## Prerequisites

- A Proxmox VE cluster or standalone host, reachable over its API (default
  port 8006).
- PowerShell 7+ (`pwsh`), on Windows, Linux, or macOS.
- Your own copy of `uagdeploy.psm1`, obtained through a valid Omnissa
  entitlement, placed in the same directory as `Get-UagUserData.ps1`.
- The UAG QCOW2 appliance image (`euc-unified-access-gateway-*.qcow2`,
  the Nutanix/OpenStack-flavored download), also from your own entitlement.
- A Proxmox storage with both the **Disk image** and **Snippets** content
  types enabled (Directory-type storages support both; LVM/LVM-Thin/ZFS do
  not support Snippets at all).

## One-time setup

### 1. Create a Proxmox API token

Routine deployments run entirely under a token, never root. Create one under
*Datacenter → Permissions → API Tokens*, with a role granting at least VM
provisioning/lifecycle rights on the target node/storage, and **uncheck**
"Privilege Separation" (a separated token additionally needs every one of
those privileges granted again explicitly on the token itself, which is
easy to miss and shows up as a 403 on the very first call).

### 2. Create the snippets delivery user (one-time, per node)

Proxmox's REST API has never supported uploading cloud-init snippet files,
on any version (see [Proxmox bugzilla #2208](https://bugzilla.proxmox.com/show_bug.cgi?id=2208),
open 7+ years, still true on current PVE 9). This tooling delivers snippets
over plain SSH instead, the same approach
[`bpg/terraform-provider-proxmox`](https://github.com/bpg/terraform-provider-proxmox)
uses for the same reason: a dedicated, unprivileged system user with exactly
one scoped `sudo` rule, nothing else.

On each Proxmox node that will host deployments:

```bash
useradd -m -s /bin/bash uag-snippets
# Must be a real shell, NOT /usr/sbin/nologin — SSH still routes a one-off
# remote command through the account's configured shell, so nologin refuses
# it identically to an interactive login ("This account is currently not
# available").

ssh-keygen -t ed25519 -f uag-snippets-key -N ''
mkdir -p /home/uag-snippets/.ssh
cp uag-snippets-key.pub /home/uag-snippets/.ssh/authorized_keys
chown -R uag-snippets:uag-snippets /home/uag-snippets/.ssh
chmod 700 /home/uag-snippets/.ssh
chmod 600 /home/uag-snippets/.ssh/authorized_keys

# via visudo -f /etc/sudoers.d/uag-snippets:
uag-snippets ALL=(root) NOPASSWD: /usr/bin/tee /var/lib/vz/snippets/[a-zA-Z0-9_][a-zA-Z0-9_.-]*
```

Adjust the `/var/lib/vz/snippets` path in the sudoers rule to match whichever
storage your deployment INI's `snippetStorage` actually points at. Keep the
private key (`uag-snippets-key`) somewhere only you can read it; it is the
only credential this account has, and it authorizes writes matching that
path pattern only.

### 3. Build the template (once per cluster/storage combination)

```powershell
pwsh ./New-UagPveTemplate.ps1 -ProxmoxHost <host> -Node <node> `
    -Storage <storage> -Qcow2Image /path/to/euc-unified-access-gateway-*.qcow2 `
    -ProxmoxPassword (Get-Credential -UserName 'root@pam').Password
```

This is the one operation in the whole pipeline that needs a real
`root@pam` login (Proxmox's `import-from` disk operation is restricted to
root regardless of API token privileges). It imports the QCOW2, converts the
result to a Proxmox template, and prints a VMID. Put that VMID in every
deployment INI's `[Platform]` → `templateVmid`.

## Deploying an instance

1. Copy `uag-pve-api-example.ini` and fill in your values (see schema
   below).
2. Run:

```powershell
pwsh ./uagdeploypve.ps1 -IniFile ./my-uag-instance.ini `
    -RootPwd 'yourRootPwd' -AdminPwd 'yourAdminPwd' `
    -ApiToken 'root@pam!uagdeploy=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
```

(Or set `$env:PVE_API_TOKEN` instead of `-ApiToken`.)

3. Wait roughly a minute or two past the console login prompt before testing
   SSH/admin-UI login — UAG's first-boot script keeps finishing password
   policy, certificate generation, and ESM key setup after the prompt
   appears; testing too early looks exactly like a missing password but
   isn't one.

## INI schema

### `[General]`

Unchanged from UAG's own documented INI format — every field the real
`uagdeploy*.ps1` scripts understand works exactly the same here (network
settings, `sshEnabled`, password policy fields, and so on). See
`uag-pve-api-example.ini` for the minimal working set.

### `[Platform]`

| Field | Required | Notes |
|---|---|---|
| `type` | yes | Must be `proxmox`. |
| `host` | yes | Proxmox API endpoint. |
| `node` | yes | Cluster node to deploy onto. |
| `vmid` | no | Pin a specific VMID; omitted = next free ID via `/cluster/nextid`. |
| `templateVmid` | yes | VMID of the template built in one-time setup. |
| `storage` | yes | Storage for the cloned VM's disk. |
| `snippetStorage` | no | Defaults to `storage`. Where the cloud-init snippet reference resolves. |
| `bridge` | yes | Network bridge for the VM's NIC. |
| `memoryMB` | yes | Memory in MB. |
| `cores` | yes | vCPU count. |
| `snippetSshUser` | yes | The user created in one-time setup step 2. |
| `snippetSshKeyPath` | yes | Path to that user's private key. |
| `snippetSshPort` | no | Defaults to 22. |
| `sshHost` | no | Defaults to `host`. Override in a multi-node cluster if the deploying node isn't reachable at the same address as the API endpoint. |

### `[Smbios]`

Optional; these are also the built-in defaults.

| Field | Default |
|---|---|
| `manufacturer` | `Nutanix` |
| `product` | `AHV` |
| `version` | `1.0` |

## Known gotchas

- **Kernel panic on `qm start`.** Requires `--cpu host` — Proxmox's default
  CPU model (`kvm64`) panics this appliance's kernel outright. Already baked
  into this tooling's hardware profile; only relevant if you're deploying by
  hand outside this tool.
- **`qm set --smbios1` rejects `version=1.0`.** Proxmox validates SMBIOS
  fields as base64; a bare `.` isn't valid base64. This tooling
  base64-encodes automatically.
- **`shpchp` messages during boot under `q35` are cosmetic**, not a hang — a
  known dual-registration race between the legacy SHPC driver and q35's
  native PCIe hotplug. Give it a minute before assuming it's stuck.
- **INI comments must use `#`, never `;`.** UAG's own `ImportIni` function
  only recognizes `#`; a `;` line isn't skipped and can crash the parser if
  it happens to contain something resembling `key=value`.

## Background / how this works

Two companion blog posts cover the full story: how UAG's own first-boot
script decides which platform it's running on independently of cloud-init,
and how this tooling's architecture (template+clone, token auth, SSH/`sudo
tee` snippet delivery) evolved through several live-testing rounds against a
real Proxmox cluster.

- *Running Omnissa Unified Access Gateway on Proxmox VE, part 1: the
  reverse-engineering story*
- *Running Omnissa Unified Access Gateway on Proxmox VE, part 2: building a
  real deployment tool*

## Credits

The `--cpu host` requirement (a hard kernel-panic fix, not a performance
tweak) was independently confirmed by **Robert Schumann**, who deployed the
same UAG appliance on his own Proxmox host via a different cloud-init
delivery mechanism and reached the same conclusion. His tested hardware
baseline (`--cpu host`, `--machine q35`, `--bios seabios`, `--scsihw
virtio-scsi-single`, `--balloon 0`) is adopted here in full.

## License and copyright

The code in this repository is original work, licensed under [choose a
license — MIT/Apache-2.0 are reasonable defaults for something like this].
UAG itself, `uagdeploy.psm1`, and every `uagdeploy*.ps1` script are Omnissa's
own copyrighted software and are not included here in any form. "Omnissa"
and "Unified Access Gateway" are trademarks of Omnissa, LLC; this project is
unaffiliated with and not endorsed by Omnissa.
