<#
.SYNOPSIS
    ONE-TIME setup: builds a Proxmox template from the golden UAG QCOW2 so
    uagdeploypve.ps1 can clone from it for every actual deployment using
    plain API-token auth.

.DESCRIPTION
    Run this once per Proxmox cluster/storage combination you deploy UAG
    onto, NOT once per deployed UAG instance. It needs a real root@pam
    login (ticket auth), because the underlying import-from operation
    (attaching the golden QCOW2 to a VM disk by raw filesystem path) is
    hard-restricted by Proxmox to that exact identity - even a fully
    privileged API token is rejected ("Only root can pass arbitrary
    filesystem paths"). That's a deliberate Proxmox security gate
    (arbitrary host-file reads into a VM disk), not a bug to route around.

    Once the template exists, every regular uagdeploypve.ps1 run clones it
    instead (a normal, ACL-respecting, non-raw-path operation), so routine
    deployments only ever need an API token.

    Does NOT modify uagdeploy.psm1. All logic lives in the separate
    uagdeploypve.psm1 add-on module next to this script, same as
    uagdeploypve.ps1.

.PARAMETER ProxmoxHost
    The Proxmox API endpoint, e.g. pve.example.com.

.PARAMETER Node
    Which cluster member to build the template VM on.

.PARAMETER Storage
    Where the template's disk should live (e.g. 'local'). Deployments
    later specify their OWN target storage for the clone - this is just
    where the one-time import lands.

.PARAMETER ProxmoxPassword
    Password for -ProxmoxUser (defaults to root@pam) as a SecureString.
    Must be a real login, not an API token - see .DESCRIPTION for why this
    parameter set still needs one. OPTIONAL - if omitted (and -ApiToken is
    also not given), the script prompts for it interactively with
    Read-Host -AsSecureString once it's running (see .NOTES for why that's
    the default instead of a command-line argument).

    If you do need to pass it as an argument (e.g. scripted/CI use), it
    MUST be built inside the SAME process that runs this script - do not
    invoke this script via a separate "pwsh ./New-UagPveTemplate.ps1 ..."
    child process with a SecureString on its command line, that cannot
    work (see .NOTES). Dot-source or call it directly in your current
    session instead: ". ./New-UagPveTemplate.ps1 -ProxmoxPassword
    $securePw ..." (with $securePw already built as a SecureString in that
    same session).

.PARAMETER ApiToken
    Proxmox API token (e.g. 'root@pam!uag=<uuid>'), as an alternative to
    -ProxmoxPassword. If Storage's content types include 'import' (PVE
    9.1+ enables this by default on installer-created storages, and it
    can be turned on manually on older ones), a token can upload the
    golden QCOW2 itself via content=import and reference the resulting
    volid instead of a raw filesystem path, avoiding the root-only
    raw-path restriction described in .DESCRIPTION, since it works
    through Proxmox's own storage management rather than an arbitrary
    path.

    NOT YET LIVE-TESTED against a real Proxmox host - the underlying
    Send-ProxmoxImportUpload function has been verified against a local
    test HTTP listener (correct streaming, Content-Length, and multipart
    framing), but not against the real API. -ProxmoxPassword is the
    proven, live-confirmed path if -ApiToken doesn't pan out or your
    storage doesn't have the 'import' content type enabled.

    Mutually exclusive with -ProxmoxPassword/-ProxmoxUser - if -ApiToken
    is given, it takes precedence and no password prompt happens.

.PARAMETER Qcow2Image
    With -ApiToken: a LOCAL path (on the machine running this script) to
    the golden QCOW2 - it gets uploaded to Storage via content=import.
    With -ProxmoxPassword (ticket auth, the fallback path): a path that
    must already exist ON THE TARGET NODE's own filesystem - ticket auth
    never uploads anything, it references the file where it already sits.

.PARAMETER TemplateVmid
    VMID to use for the template. Omit to auto-assign via
    /cluster/nextid - either way, the resulting VMID is printed at the
    end and must be recorded.

.PARAMETER Force
    If TemplateVmid is given explicitly and already exists, stop and
    destroy it first for a clean rebuild. Without this, an in-use
    explicit VMID is a hard error (safety net against accidentally
    clobbering something unrelated).

.EXAMPLE
    pwsh ./New-UagPveTemplate.ps1 `
        -ProxmoxHost pve.example.com -Node pve-node1 -Storage local `
        -Qcow2Image /var/lib/vz/images/euc-unified-access-gateway-<version>.qcow2

    Prompts for the root@pam password interactively - no password on the
    command line at all, so the SecureString never has to cross a process
    boundary. Add the printed "templateVmid=<N>" line to [Platform] in
    every deployment INI that should clone from this template.

.EXAMPLE
    pwsh ./New-UagPveTemplate.ps1 `
        -ProxmoxHost pve.example.com -Node pve-node1 -Storage local `
        -ApiToken 'root@pam!uag=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
        -Qcow2Image C:\images\euc-unified-access-gateway-<version>.qcow2

    Token-only alternative - uploads the QCOW2 (a LOCAL path here, not a
    node-side one) via content=import instead of using a root login. See
    .PARAMETER ApiToken: NOT yet live-tested, try -ProxmoxPassword if this
    doesn't work or your storage lacks the 'import' content type.

.NOTES
    Part of a template+clone design - see uagdeploypve.psm1's
    New-UagProxmoxTemplate for the underlying logic. The ticket/password
    path (import-from + hull creation + convert-to-template) is
    live-confirmed against a real Proxmox host. The -ApiToken/content=import
    path is new and not yet live-tested - see .PARAMETER ApiToken.

    A SecureString cannot survive being passed to a new "pwsh
    ./New-UagPveTemplate.ps1 ..." child process on the command line:
    every argument is flattened to plain text before the child process
    sees it, so what actually arrives is the literal string
    "System.Security.SecureString", and PowerShell's own parameter binder
    then fails trying to convert that text back to a [securestring].
    -ProxmoxPassword is optional for this reason - when omitted, it's
    prompted for with Read-Host -AsSecureString inside the same process
    that actually uses it, so nothing has to cross a process boundary as
    an object at all.
#>
param(
    [Parameter(Mandatory)] [string]$ProxmoxHost,
    [Parameter(Mandatory)] [string]$Node,
    [Parameter(Mandatory)] [string]$Storage,
    [Parameter(Mandatory)] [string]$Qcow2Image,
    [securestring]$ProxmoxPassword,   # optional - prompted for below if not given and -ApiToken isn't used either, see .PARAMETER ProxmoxPassword
    [string]$ApiToken,                # optional alternative to -ProxmoxPassword - see .PARAMETER ApiToken. NOT YET LIVE-TESTED.
    [string]$ProxmoxUser = 'root@pam',
    [string]$TemplateVmid,
    [string]$TemplateName = 'uag-template',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent (Resolve-Path $PSCommandPath)

$kvmModule = Join-Path $ScriptDir 'uagdeploypve.psm1'
if (-not (Test-Path $kvmModule)) { throw "uagdeploypve.psm1 not found next to this script ($ScriptDir)." }
Import-Module $kvmModule -Force

if ($ApiToken) {
    # Token path - content=import upload, no root login at all. NOT YET
    # LIVE-TESTED; the underlying streamed upload has only been verified
    # against a local test HTTP listener, not against actual Proxmox.
    Write-Host "Using API token auth against $ProxmoxHost (content=import upload path - not yet live-verified, see .PARAMETER ApiToken)..."
    $context = New-ProxmoxApiContext -ProxmoxHost $ProxmoxHost -ApiToken $ApiToken
}
else {
    if (-not $ProxmoxPassword) {
        # Prompted for HERE, inside this process, on purpose - see .NOTES
        # for why a SecureString passed in on the command line to "pwsh
        # ./New-UagPveTemplate.ps1 ..." (a separate child process)
        # can never work.
        $ProxmoxPassword = Read-Host -AsSecureString -Prompt "Proxmox password for $ProxmoxUser"
    }
    Write-Host "Logging in to $ProxmoxHost as $ProxmoxUser (ticket auth)..."
    $context = New-ProxmoxTicketContext -ProxmoxHost $ProxmoxHost -Username $ProxmoxUser -Password $ProxmoxPassword
}

$vmid = New-UagProxmoxTemplate -Context $context -Node $Node -Storage $Storage -Qcow2Image $Qcow2Image `
    -TemplateVmid $TemplateVmid -TemplateName $TemplateName -Force:$Force

Write-Host ''
Write-Host "Template ready. Add this to [Platform] in your deployment INIs:"
Write-Host "  templateVmid=$vmid"
