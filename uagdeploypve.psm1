<#
.SYNOPSIS
    Add-on module for deploying UAG to Proxmox VE via its REST API.

    This is a NEW, standalone module - it does NOT modify or replace
    uagdeploy.psm1 (Omnissa's own module, the one that ships with UAG and
    that Get-UagUserData.ps1 already reuses for the vSphere/Nutanix/
    OpenStack payload logic). It only ever calls into that module's
    existing exported functions (ImportIni) from the outside, and is
    otherwise completely independent, so a future update to the real
    uagdeploy.psm1 stays a drop-in replacement with nothing here to
    reconcile.

.NOTES
    Deployment works by template+clone, not by importing the golden QCOW2
    on every run:

    - New-UagProxmoxTemplate does the (privileged) import ONCE, converts
      the result into a Proxmox template, and every actual deployment
      (New-UagVmOnProxmox) CLONES it instead. Clone is a normal,
      ACL-respecting, non-raw-path operation, so a plain API token
      handles it. This also means the golden QCOW2 only has to exist in
      one place (a template clones correctly cluster-wide).

    - Cloud-init SNIPPETS have never been uploadable via Proxmox's REST
      API, on any version (see Send-UagSnippetsOverSsh) - a permanent
      platform gap, not something a different request shape works around.
      Snippets are delivered over SSH instead, to a dedicated non-root
      user with one scoped sudoers rule, the same mechanism
      bpg/terraform-provider-proxmox uses for the identical gap.

    Every hardware setting baked in here (cpu=host, machine=q35,
    bios=seabios, scsihw=virtio-scsi-single, balloon=0, base64-encoded
    smbios1 fields, both cloud-init snippets attached) is a validated
    profile confirmed against a real Proxmox host, not a guess.

    Live-confirmed end to end: ticket auth, hull creation + raw-path
    import-from, template conversion, clone, post-clone hardware/smbios
    reconfiguration, and SSH/sudo+tee snippet delivery. NOT yet
    live-tested: Send-ProxmoxImportUpload (the token-based upload path for
    the golden image) and the resulting token-only template creation path
    in New-UagProxmoxTemplate - both flagged inline where relevant. The
    ticket/password path remains the proven way to build a template.
#>

# ---------------------------------------------------------------------------
# Low-level API plumbing
# ---------------------------------------------------------------------------

function New-ProxmoxApiContext {
    <#
    .SYNOPSIS
        Bundles what every API call needs (base URL, auth header, whether
        to skip TLS verification for a self-signed cert) into one object,
        so the functions below take a single -Context instead of three
        separate parameters each.

        This is the context every REGULAR deployment should use
        (New-UagVmOnProxmox) - a normal, non-root API token is enough
        now that deployment clones a template instead of importing a
        raw file. Only the one-time New-UagProxmoxTemplate step still
        needs New-ProxmoxTicketContext below.
    #>
    param(
        [Parameter(Mandatory)] [string]$ProxmoxHost,   # e.g. "pve.example.com"
        [Parameter(Mandatory)] [string]$ApiToken,       # full "USER@REALM!TOKENID=SECRET" string, exactly as shown once by the Proxmox UI when the token is created (Datacenter -> Permissions -> API Tokens)
        [int]$Port = 8006,
        [bool]$AllowInsecureTls = $true                 # self-signed cert is the norm for a lab Proxmox host; set $false once a real cert is in place
    )

    [PSCustomObject]@{
        BaseUri  = "https://${ProxmoxHost}:${Port}/api2/json"
        Headers  = @{ Authorization = "PVEAPIToken=$ApiToken" }
        Insecure = $AllowInsecureTls
        # Lets New-UagProxmoxTemplate pick the right upload strategy just
        # from which kind of context it was given - see its own header.
        AuthType = 'token'
    }
}

function New-ProxmoxTicketContext {
    <#
    .SYNOPSIS
        Authenticates as an actual user via a real username+password login
        (ticket/cookie auth), instead of an API token. Returns the same
        shape of context object as New-ProxmoxApiContext, so it's a
        drop-in -Context for every function below.

        A FALLBACK now, not the primary path, for New-UagProxmoxTemplate's
        one-time setup step. The primary path there uploads the golden
        QCOW2 to the storage's 'import' content type and references the
        resulting volid (storage:import/filename) - a normal,
        ACL-respecting storage reference that works fine with a plain API
        token (New-ProxmoxApiContext): a Proxmox developer has confirmed
        on the community forum that this avoids the root-only filesystem
        path restriction, since it works within Proxmox's own storage
        management rather than passing an arbitrary filesystem path.

        This function (and the raw-path import-from it enables) is still
        needed as a fallback for hosts where the 'import' content type
        isn't enabled on the target storage, or if that upload path turns
        out not to work as expected. Proxmox restricts import-from with a
        RAW filesystem path to the literal 'root@pam' identity
        specifically - an API token's effective identity is
        'root@pam!<tokenid>', which fails that check even with full
        privileges and privilege separation disabled (confirmed live:
        the identical config change failed with a token and succeeded
        with a ticket for the same root@pam account).

        The cloud-init SNIPPETS upload gap (see Send-UagSnippetsOverSsh)
        is a separate, permanent limitation, confirmed still present on
        current Proxmox VE releases via Proxmox's own bugzilla and
        community forum.
    #>
    param(
        [Parameter(Mandatory)] [string]$ProxmoxHost,
        [Parameter(Mandatory)] [string]$Username,        # e.g. "root@pam"
        [Parameter(Mandatory)] [securestring]$Password,
        [int]$Port = 8006,
        [bool]$AllowInsecureTls = $true
    )

    $baseUri = "https://${ProxmoxHost}:${Port}/api2/json"
    # [System.Net.NetworkCredential] is the standard, safe way to get a
    # SecureString's plaintext back out in PowerShell 7+, without manually
    # marshaling/freeing a BSTR pointer.
    $plainPassword = [System.Net.NetworkCredential]::new('', $Password).Password

    $ticketParams = @{
        Uri                  = "$baseUri/access/ticket"
        Method               = 'POST'
        Body                 = @{ username = $Username; password = $plainPassword }
        SkipHeaderValidation = $true
    }
    if ($AllowInsecureTls) { $ticketParams.SkipCertificateCheck = $true }

    $response = Invoke-RestMethod @ticketParams
    if (-not $response.data.ticket) { throw "Proxmox login failed for '$Username' - check the username/password." }

    [PSCustomObject]@{
        BaseUri  = $baseUri
        Headers  = @{
            Cookie              = "PVEAuthCookie=$($response.data.ticket)"
            CSRFPreventionToken = $response.data.CSRFPreventionToken
        }
        Insecure = $AllowInsecureTls
        AuthType = 'ticket'
    }
}

function Invoke-ProxmoxApi {
    <#
    .SYNOPSIS
        Thin wrapper around Invoke-RestMethod: adds the auth header and
        base URL, and surfaces Proxmox's own JSON error body instead of a
        generic HTTP exception when a call fails.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Path,            # e.g. "/nodes/pve1/qemu"
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE')] [string]$Method = 'GET',
        [hashtable]$Body = $null,
        [hashtable]$Form = $null                         # for multipart/form-data uploads (snippets)
    )

    $uri = $Context.BaseUri + $Path
    $params = @{
        Uri     = $uri
        Method  = $Method
        Headers = $Context.Headers
        # PVEAPIToken values contain "@" and "!" (e.g.
        # "PVEAPIToken=root@pam!UAG=<secret>"), which are not valid
        # characters in .NET's strict RFC 7230 header-token validation for
        # the "Authorization" header specifically. Without this, the
        # header is rejected client-side before any network call is even
        # attempted ("The format of value '...' is invalid."). This does
        # not relax TLS/cert checking, only the header *value* format
        # check.
        SkipHeaderValidation = $true
    }
    if ($Context.Insecure) { $params.SkipCertificateCheck = $true }
    if ($Form) {
        $params.Form = $Form
    }
    elseif ($Body) {
        # Invoke-RestMethod form-encodes a hashtable Body by default, which
        # is what the PVE API expects (not JSON) for these endpoints.
        $params.Body = $Body
    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        $respBody = $null
        try { $respBody = $_.ErrorDetails.Message } catch {}
        $detail = if ($respBody) { "`nResponse: $respBody" } else { '' }
        throw "Proxmox API call failed: $Method $Path`n$($_.Exception.Message)$detail"
    }
}

function Wait-ProxmoxTask {
    <#
    .SYNOPSIS
        Most write operations on the PVE API (create, config changes that
        touch disks, start/stop, delete, clone) are asynchronous: they
        return a task ID (UPID) immediately and keep running server-side.
        This polls /nodes/{node}/tasks/{upid}/status until the task
        leaves "running", then throws if it did not finish OK. Unlike the
        `qm` CLI (which blocks until done), every one of these calls needs
        this wrapped around it or the next step can race a task still in
        progress (e.g. starting a VM whose clone hasn't finished).
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string]$Upid,
        [int]$TimeoutSec = 600,
        [int]$PollIntervalSec = 3
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $encodedUpid = [uri]::EscapeDataString($Upid)
        $status = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$Node/tasks/$encodedUpid/status"
        if ($status.data.status -eq 'stopped') {
            if ($status.data.exitstatus -ne 'OK') {
                throw "Proxmox task $Upid failed: $($status.data.exitstatus)"
            }
            return
        }
        Start-Sleep -Seconds $PollIntervalSec
    }
    throw "Proxmox task $Upid did not finish within ${TimeoutSec}s"
}

function Send-ProxmoxFileUpload {
    <#
    .SYNOPSIS
        Uploads a file to a Proxmox storage's upload endpoint
        (POST /nodes/{node}/storage/{storage}/upload), by hand-building
        the multipart/form-data request body as a single byte array
        instead of using Invoke-RestMethod's -Form parameter.

        WHY: -Form builds the request as a System.Net.Http.
        MultipartFormDataContent with the file wrapped in a StreamContent
        part, which .NET sends with Transfer-Encoding: chunked (no
        Content-Length) rather than a fixed-length body. Proxmox's own API
        server (PVE::APIServer::AnyEvent, not a general-purpose HTTP
        server) does not handle a chunked request body on this endpoint -
        it fails with a generic, unhelpful 500 for an otherwise perfectly
        valid multipart body. Fixed by sending a single byte[] body with a
        real Content-Length instead of a chunked stream.

        SCOPE: this loads the whole file into memory, so it's only
        appropriate for small files - fine for the content types this
        endpoint's own 'content' parameter actually accepts ('iso,
        vztmpl, import' - 'snippets' is NOT a valid value here at all, a
        hard Proxmox API limitation, see Send-UagSnippetsOverSsh for how
        snippets are actually delivered instead). For a large file (e.g.
        a multi-GB disk image uploaded as content=import), use
        Send-ProxmoxImportUpload instead - that one streams from disk
        with an explicit Content-Length rather than buffering the whole
        file in memory.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Path,          # e.g. "/nodes/pve1/storage/local/upload"
        [Parameter(Mandatory)] [string]$ContentType,   # Proxmox's 'content' form field, e.g. "snippets"
        [Parameter(Mandatory)] [string]$FilePath        # local file to upload; its own name becomes the destination filename
    )

    $boundary = [System.Guid]::NewGuid().ToString()
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $nl = "`r`n"

    # Built by hand, not via -Form, specifically so the whole thing ends
    # up as one concrete byte[] with a known length up front - see the
    # SYNOPSIS above for why that distinction is what actually matters
    # here.
    $preamble = (
        "--$boundary$nl" +
        "Content-Disposition: form-data; name=`"content`"$nl$nl" +
        "$ContentType$nl" +
        "--$boundary$nl" +
        "Content-Disposition: form-data; name=`"filename`"; filename=`"$fileName`"$nl" +
        "Content-Type: application/octet-stream$nl$nl"
    )
    $epilogue = "$nl--$boundary--$nl"
    # PowerShell's "+" on typed arrays does NOT preserve the element type -
    # [byte[]] + [byte[]] silently produces a System.Object[], which is
    # NOT the same thing to Invoke-RestMethod's -Body parameter (it needs
    # a real byte[] to send a fixed-length body). Concatenate through a
    # MemoryStream instead so the result is guaranteed an actual byte[].
    $preambleBytes = [Text.Encoding]::UTF8.GetBytes($preamble)
    $epilogueBytes = [Text.Encoding]::UTF8.GetBytes($epilogue)
    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($preambleBytes, 0, $preambleBytes.Length)
    $ms.Write($fileBytes, 0, $fileBytes.Length)
    $ms.Write($epilogueBytes, 0, $epilogueBytes.Length)
    [byte[]]$bodyBytes = $ms.ToArray()

    $params = @{
        Uri                  = $Context.BaseUri + $Path
        Method               = 'POST'
        Headers              = $Context.Headers
        ContentType          = "multipart/form-data; boundary=$boundary"
        Body                 = $bodyBytes
        SkipHeaderValidation = $true
    }
    if ($Context.Insecure) { $params.SkipCertificateCheck = $true }

    try {
        Invoke-RestMethod @params
    }
    catch {
        $respBody = $null
        try { $respBody = $_.ErrorDetails.Message } catch {}
        $detail = if ($respBody) { "`nResponse: $respBody" } else { '' }
        throw "Proxmox file upload failed: POST $Path`n$($_.Exception.Message)$detail"
    }
}

function Send-ProxmoxImportUpload {
    <#
    .SYNOPSIS
        Uploads a (potentially very large - tens of GB) disk image to a
        Proxmox storage's 'import' content type
        (POST /nodes/{node}/storage/{storage}/upload, content=import),
        streamed straight from disk with an explicit Content-Length, so
        it never buffers the whole file in memory the way
        Send-ProxmoxFileUpload does (fine for a small YAML snippet,
        completely impractical for a 20+GB QCOW2).

        WHY THIS EXISTS: New-ProxmoxTicketContext's import-from-with-a-
        raw-path approach needs a real root login and the image already
        sitting on the node's own filesystem, prepared out of band. A
        Proxmox developer has confirmed on the community forum that
        uploading to the 'import' content type and referencing the
        resulting volid (storage:import/filename) instead of a raw path
        avoids the root-only filesystem path restriction, since it works
        within Proxmox's own storage management rather than an arbitrary
        filesystem path - i.e. a plain API token should be able to do the
        whole thing, and the image can be uploaded directly from wherever
        this script runs instead of being staged on the node by hand
        first. New-UagProxmoxTemplate uses this as its primary path when
        given a token context, falling back to the raw-path/ticket
        approach otherwise.

        HOW THE STREAMING WORKS: uses System.Net.Http.HttpClient directly
        (not Invoke-RestMethod, which has no way to both stream a large
        file AND declare its Content-Length up front). The file is opened
        as a read-only FileStream and wrapped in a StreamContent whose
        Headers.ContentLength is set explicitly to the file's real size -
        when every part of a MultipartFormDataContent reports a known
        length like this, .NET computes and sends a real Content-Length
        for the whole request instead of switching to chunked transfer
        encoding. That distinction is exactly what breaks a naive upload
        against Proxmox's AnyEvent-based API server (see
        Send-ProxmoxFileUpload) and would be far more likely to bite at
        multi-GB scale if this used the same naive -Form path instead.

        NOT YET LIVE-TESTED against a real Proxmox host. Test with a
        small file first (to prove the token/permissions/volid mechanics
        cheaply) before trusting it with a full-size QCOW2 upload.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Path,           # e.g. "/nodes/pve1/storage/local/upload"
        [Parameter(Mandatory)] [string]$FilePath,       # local file to upload; its own name becomes the destination filename
        [string]$ContentType = 'import',
        [int]$TimeoutMinutes = 180                       # generous - a multi-GB upload over a real network link can take a while
    )

    if (-not (Test-Path $FilePath)) { throw "File not found: $FilePath" }
    $fileInfo = Get-Item $FilePath
    $fileName = $fileInfo.Name

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $handler = [System.Net.Http.HttpClientHandler]::new()
    if ($Context.Insecure) {
        # Same "self-signed lab cert" allowance Invoke-ProxmoxApi's
        # -SkipCertificateCheck makes elsewhere - explicit opt-in via the
        # context, not a blanket default.
        $handler.ServerCertificateCustomValidationCallback = { $true }
    }

    $client = $null
    $fileStream = $null
    try {
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromMinutes($TimeoutMinutes)
        foreach ($h in $Context.Headers.GetEnumerator()) {
            # TryAddWithoutValidation, not Add - same reason Invoke-ProxmoxApi
            # needs -SkipHeaderValidation: PVEAPIToken values contain "@"/"!"
            # which .NET's strict header validation otherwise rejects.
            $client.DefaultRequestHeaders.TryAddWithoutValidation($h.Key, $h.Value) | Out-Null
        }

        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
        $fileContent.Headers.ContentLength = $fileInfo.Length
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
        # Neither .Add(content, name, filename) NOR building a
        # ContentDispositionHeaderValue object and setting .Name/.FileName
        # produces QUOTED values (name="filename") here: .NET's formatter
        # only quotes a parameter value when the token itself requires it
        # (spaces, etc.), and "content"/"filename" don't, so it legally
        # emits name=content unquoted. That's valid per RFC 7231, but
        # Proxmox's own multipart parser has only been proven to correctly
        # parse the QUOTED style (confirmed via the hand-built snippet
        # upload, which got back a clean, correctly-parsed 400 rather than
        # a garbled one), and given its already-confirmed non-standard
        # behavior elsewhere (the chunked-encoding issue in
        # Send-ProxmoxFileUpload), don't trust it to accept the unquoted
        # form too. Setting the header as a raw string via
        # TryAddWithoutValidation bypasses .NET's formatter entirely, so
        # the quoting is exactly what's already proven to work.
        $fileContent.Headers.TryAddWithoutValidation('Content-Disposition', "form-data; name=`"filename`"; filename=`"$fileName`"") | Out-Null

        $contentFieldContent = [System.Net.Http.StringContent]::new($ContentType)
        $contentFieldContent.Headers.ContentType = $null   # StringContent defaults to text/plain; charset=utf-8 - drop it, Proxmox expects a plain form field, not a typed part
        $contentFieldContent.Headers.TryAddWithoutValidation('Content-Disposition', 'form-data; name="content"') | Out-Null

        $multipart = [System.Net.Http.MultipartFormDataContent]::new()
        $multipart.Add($contentFieldContent)
        $multipart.Add($fileContent)

        $uri = $Context.BaseUri + $Path
        Write-Host "Uploading $FilePath ($([math]::Round($fileInfo.Length / 1GB, 2)) GB) to $uri ..."
        $response = $client.PostAsync($uri, $multipart).GetAwaiter().GetResult()
        $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        if (-not $response.IsSuccessStatusCode) {
            throw "Proxmox import upload failed: POST $Path`nStatus: $([int]$response.StatusCode) $($response.StatusCode)`nResponse: $responseBody"
        }
        if ($responseBody) { $responseBody | ConvertFrom-Json }
    }
    finally {
        if ($fileStream) { $fileStream.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

function Get-ProxmoxNextVmid {
    <#
    .SYNOPSIS
        Asks Proxmox for the next free VMID cluster-wide, instead of one
        being hardcoded in the INI.
    #>
    param([Parameter(Mandatory)] $Context)
    (Invoke-ProxmoxApi -Context $Context -Path '/cluster/nextid').data
}

function Test-ProxmoxVmidInUse {
    <#
    .SYNOPSIS
        Checks whether a given VMID already exists ANYWHERE in the
        cluster (not just on one node), so a manually-chosen VMID can be
        validated before it's used. Standalone and usable on its own, e.g.:
            Test-ProxmoxVmidInUse -Context $ctx -Vmid 999
        Uses /cluster/resources (cluster-wide) rather than a single node's
        /qemu/{vmid}/status/current, which would miss a VMID that exists
        on a *different* node than the one this deployment targets.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [int]$Vmid
    )
    $resources = Invoke-ProxmoxApi -Context $Context -Path '/cluster/resources?type=vm'
    [bool]($resources.data | Where-Object { $_.vmid -eq $Vmid })
}

function Resolve-ProxmoxVmid {
    <#
    .SYNOPSIS
        Shared VMID-resolution + collision-check logic, used by both
        New-UagProxmoxTemplate and New-UagVmOnProxmox so the "explicit
        VMID that's already in use" safety behavior (throw unless
        -Force, then stop+delete before rebuilding) lives in exactly one
        place instead of being copy-pasted between them.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Node,
        [string]$ExplicitVmid,   # e.g. Platform.vmid / Platform.templateVmid - $null/empty means "auto-assign"
        [switch]$Force
    )

    if (-not $ExplicitVmid) {
        return Get-ProxmoxNextVmid -Context $Context
    }

    $vmid = [int]$ExplicitVmid
    $inUse = Test-ProxmoxVmidInUse -Context $Context -Vmid $vmid
    if ($inUse) {
        if (-not $Force) {
            throw "VMID $vmid already exists. If this is a previous run of THIS deployment " + `
                "and you want it stopped and rebuilt, re-run with -Force. If it might be " + `
                "something else (a typo, another VM on a shared host), pick a different VMID " + `
                "instead - or remove the VMID setting entirely to get a fresh one automatically " + `
                "from /cluster/nextid."
        }
        Write-Host "VMID $vmid already exists and -Force was given - stopping/removing it for a clean rebuild."
        try {
            $stopResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$Node/qemu/$vmid/status/stop" -Method POST
            if ($stopResult.data) { Wait-ProxmoxTask -Context $Context -Node $Node -Upid $stopResult.data }
        }
        catch {}
        $deleteResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$Node/qemu/$vmid" -Method DELETE -Body @{ purge = 1 }
        if ($deleteResult.data) { Wait-ProxmoxTask -Context $Context -Node $Node -Upid $deleteResult.data }
    }
    return $vmid
}

function ConvertTo-ProxmoxBase64 {
    <#
    .SYNOPSIS
        qm/the API validate smbios1's manufacturer/product/version as
        base64-encoded strings - plain "1.0" is REJECTED (contains a
        "."). Always encode, always pass base64=1 alongside it.
    #>
    param([Parameter(Mandatory)] [string]$PlainText)
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($PlainText))
}

function Get-UagSmbios1Value {
    <#
    .SYNOPSIS
        Builds the smbios1 config string from a parsed [Smbios] section
        (or $null to fall back to the validated defaults: Nutanix / AHV /
        1.0). Shared by New-UagProxmoxTemplate and New-UagVmOnProxmox.
    #>
    param([hashtable]$Smbios)
    $manufacturer = if ($Smbios -and $Smbios.manufacturer) { $Smbios.manufacturer } else { 'Nutanix' }
    $product      = if ($Smbios -and $Smbios.product) { $Smbios.product } else { 'AHV' }
    $version      = if ($Smbios -and $Smbios.version) { $Smbios.version } else { '1.0' }
    'manufacturer=' + (ConvertTo-ProxmoxBase64 $manufacturer) + `
        ',product=' + (ConvertTo-ProxmoxBase64 $product) + `
        ',version=' + (ConvertTo-ProxmoxBase64 $version) + ',base64=1'
}

# ---------------------------------------------------------------------------
# One-time setup: golden QCOW2 -> Proxmox template
# ---------------------------------------------------------------------------

function New-UagProxmoxTemplate {
    <#
    .SYNOPSIS
        ONE-TIME setup: imports the golden UAG QCOW2 into a VM on Proxmox
        and converts it into a template, so every actual deployment
        (New-UagVmOnProxmox) can clone it using plain API-token auth
        instead of needing a real root login on every run. Run this once
        per Proxmox cluster/storage combination you deploy UAG onto - NOT
        once per deployed UAG instance. See New-UagPveTemplate.ps1 for
        the standalone script wrapping this.

    .PARAMETER Context
        Which kind of context you pass CHANGES how the disk gets onto
        Proxmox, automatically (checked via $Context.AuthType):

        - New-ProxmoxApiContext (a token) - PRIMARY path. Uploads
          -Qcow2Image (a LOCAL file path, read from wherever this runs)
          to the target storage's 'import' content type via
          Send-ProxmoxImportUpload, then references the resulting volid
          (storage:import/filename) in import-from - a normal storage
          reference, not a raw filesystem path, so it isn't subject to
          the root-only restriction. No root credentials needed anywhere
          in this path. NOT YET LIVE-TESTED - see
          Send-ProxmoxImportUpload's header.

        - New-ProxmoxTicketContext (a real root@pam login) - FALLBACK
          path, for a storage where 'import' isn't enabled as a content
          type, or if the upload path above doesn't pan out live.
          -Qcow2Image must then be a path already sitting on the TARGET
          NODE's own filesystem (not uploaded - referenced directly via
          a raw path), which Proxmox restricts to the literal root@pam
          identity - the proven, live-confirmed path.

    .PARAMETER TemplateVmid
        VMID to use for the template VM. Omit to auto-assign via
        /cluster/nextid. Whatever VMID this ends up as (printed at the
        end, and returned) goes into every deployment INI's [Platform]
        templateVmid field.

    .PARAMETER Smbios
        Same [Smbios] shape as New-UagVmOnProxmox. Baked into the
        template so every clone inherits it, but New-UagVmOnProxmox also
        re-applies it explicitly post-clone (belt and suspenders - keeps
        deploy-time Smbios overrides working even if a template was built
        with different values).
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string]$Storage,
        [Parameter(Mandatory)] [string]$Qcow2Image,
        [string]$TemplateVmid,
        [string]$TemplateName = 'uag-template',
        [hashtable]$Smbios,
        [switch]$Force
    )

    $vmid = Resolve-ProxmoxVmid -Context $Context -Node $Node -ExplicitVmid $TemplateVmid -Force:$Force
    $vmidSource = if ($TemplateVmid) { '' } else { ' (auto-assigned via /cluster/nextid)' }
    Write-Host "Using template VMID $vmid$vmidSource"

    $smbios1Value = Get-UagSmbios1Value -Smbios $Smbios

    if ($Context.AuthType -eq 'token') {
        # Primary path: upload to content=import, reference the volid.
        # storage:import/<filename> is Proxmox's own naming convention
        # for an uploaded import-content volume - not yet live-confirmed,
        # see Send-ProxmoxImportUpload's "NOT YET LIVE-TESTED" note.
        Write-Host "== 1/3: Uploading $Qcow2Image to '$Storage' (content=import) - a real streamed upload, can take a while =="
        Send-ProxmoxImportUpload -Context $Context -Path "/nodes/$Node/storage/$Storage/upload" -FilePath $Qcow2Image | Out-Null
        $importFromValue = "${Storage}:import/$([System.IO.Path]::GetFileName($Qcow2Image))"
        Write-Host "Uploaded. Referencing it as $importFromValue (a storage volid, not a raw path - no root needed for this)."
    }
    else {
        # Fallback path: raw filesystem path, root/ticket-only - see
        # New-ProxmoxTicketContext's header for why.
        Write-Host "== 1/3: Using ticket auth's raw-path import-from (fallback path - see .PARAMETER Context) =="
        $importFromValue = $Qcow2Image
    }

    # Same validated hardware profile as a regular deployment (cpu=host,
    # q35, seabios, virtio-scsi-single, balloon=0). net0's bridge here is
    # a placeholder only - every clone reconfigures it post-clone in
    # New-UagVmOnProxmox, since the template itself is never started or
    # deployed anywhere.
    $createBody = @{
        vmid    = $vmid
        name    = $TemplateName
        memory  = 4096
        cores   = 2
        cpu     = 'host'
        machine = 'q35'
        bios    = 'seabios'
        balloon = 0
        scsihw  = 'virtio-scsi-single'
        ostype  = 'l26'
        net0    = 'virtio,bridge=vmbr0'
        scsi0   = "${Storage}:0,import-from=$importFromValue"
        boot    = 'order=scsi0'
        smbios1 = $smbios1Value
    }
    Write-Host "== 2/3: Creating template source VM $vmid (disk import via import-from) =="
    $createResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$Node/qemu" -Method POST -Body $createBody
    if ($createResult.data) { Wait-ProxmoxTask -Context $Context -Node $Node -Upid $createResult.data -TimeoutSec 1800 }

    # Confirmed live: POST .../qemu/{vmid}/template is the direct API
    # equivalent of `qm template <vmid>` - converts the VM in place into a
    # template (disks become read-only base images for clones). Ran
    # synchronously (no UPID) in live testing, as expected for a
    # metadata/disk flag change rather than a data copy - still handled
    # defensively below in case a future Proxmox version makes it async.
    Write-Host "== 3/3: Converting VM $vmid to a template =="
    $templateResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$Node/qemu/$vmid/template" -Method POST
    if ($templateResult.data) { Wait-ProxmoxTask -Context $Context -Node $Node -Upid $templateResult.data }

    Write-Host ''
    Write-Host "Done. VMID $vmid is now a template ('$TemplateName')."
    Write-Host "Put this in [Platform] of every deployment INI that should clone from it:"
    Write-Host "  templateVmid=$vmid"

    return $vmid
}

function Get-ProxmoxStoragePath {
    <#
    .SYNOPSIS
        Resolves a Proxmox storage ID (e.g. 'local') to its real
        filesystem path on the node (e.g. '/var/lib/vz'), by reading the
        storage's own config via the API (GET /storage/{storage}) - a
        normal, unprivileged read, not a special permission.

    .DESCRIPTION
        Needed because Send-UagSnippetsOverSsh writes to the snippets
        directory directly over SSH (there is no API for it at all - see
        that function's docstring), so it needs the REAL absolute path,
        not just the storage's short ID. Resolving it via the API instead
        of asking for it as a separate INI field keeps a single source of
        truth (Proxmox's own storage.cfg) rather than a value that could
        silently drift out of sync if someone changes the storage
        definition later without also updating an INI.

        Only works for directory-backed storage types (dir, nfs, cifs -
        the same types that can have the 'snippets' content type enabled
        at all); throws a clear error if the storage's config has no
        'path' field (e.g. it's LVM/ZFS-backed, which can't hold snippets
        in the first place).
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Storage
    )
    $result = Invoke-ProxmoxApi -Context $Context -Path "/storage/$Storage"
    if (-not $result.data.path) {
        throw "Storage '$Storage' has no filesystem 'path' in its Proxmox config (GET /storage/$Storage). " + `
            "Snippet delivery over SSH only works for directory-backed storage (dir/nfs/cifs) - the same " + `
            "types that support the 'snippets' content type in the first place."
    }
    return $result.data.path
}

function Send-UagSnippetsOverSsh {
    <#
    .SYNOPSIS
        Delivers the two per-deployment cloud-init snippet files (user
        and meta) to the target node's real snippets directory over SSH,
        using a non-root login that only has passwordless sudo rights to
        write into that one directory - not root, and not the Proxmox API
        at all.

    .DESCRIPTION
        WHY THIS EXISTS AT ALL: Proxmox's REST API has never supported
        uploading snippet files, on any version - the 'content' parameter
        on the upload endpoint only accepts 'iso, vztmpl, import',
        'snippets' is not a valid value. This is a long-standing, publicly
        tracked gap in Proxmox's own API (see Proxmox's bugzilla and
        community forum), confirmed still present on current releases -
        not something to wait on or route around cleverly, so snippet
        delivery has to go through the filesystem some other way.

        WHY THIS EXACT MECHANISM (sudo + tee over SSH exec, not a chrooted
        SFTP jail): a dedicated chrooted SFTP-only user (OpenSSH
        ChrootDirectory + ForceCommand internal-sftp) also works, but the
        most widely used Terraform/OpenTofu provider for Proxmox
        (bpg/terraform-provider-proxmox) hits this exact same API gap and
        solves it more simply, with a non-root SSH user that has ONE
        narrowly scoped sudoers rule, e.g.:

            terraform ALL=(root) NOPASSWD: /usr/bin/tee /var/lib/vz/snippets/[a-zA-Z0-9_][a-zA-Z0-9_.-]*

        and pipes the file's content into `sudo tee <path>` over a plain
        SSH exec session instead of using SFTP at all. That's simpler to
        set up on the node (one useradd, one sudoers line - no chroot
        directory tree, no ForceCommand, no ChrootDirectory ownership
        rules to get right) and is a pattern any admin who has used that
        provider will already recognize. Adopted here for the same
        reasons.

        The regex-anchored filename in the sudoers rule is deliberate and
        load-bearing: a wildcard pattern like '/var/lib/vz/*' is
        exploitable via path traversal (e.g.
        '/var/lib/vz/../../../etc/sudoers.d/malicious'), which can
        escalate straight to root. This function re-validates every
        destination filename against that same safe-character pattern
        BEFORE it ever reaches the network, as defense in depth - if the
        sudoers rule on the node is ever loosened by mistake, this
        client-side check is a second gate, not the only one.

        HOW: for each file, shells out to the Windows OpenSSH client's
        ssh.exe with the file's content piped in as stdin (via
        -RedirectStandardInput, which reads bytes directly from disk - no
        PowerShell text-pipeline involved, so this is binary-safe and
        doesn't risk mangled line endings), running a single remote
        command: sudo tee "<remoteDir>/<filename>" > /dev/null. No extra
        module needed beyond what Windows 10/11 already ships.
        -o BatchMode=yes means this fails fast with a clear error instead
        of hanging on an unexpected password/interactive prompt (e.g. if
        the sudoers NOPASSWD rule isn't actually in place on the node).
    #>
    param(
        [Parameter(Mandatory)] [string]$SshHost,
        [Parameter(Mandatory)] [string]$SshUser,
        [Parameter(Mandatory)] [string]$SshKeyPath,
        [int]$SshPort = 22,
        [Parameter(Mandatory)] [string]$RemoteDir,      # e.g. '/var/lib/vz/snippets' - see Get-ProxmoxStoragePath
        [Parameter(Mandatory)] [string[]]$LocalFiles    # uploaded under their own filename, one 'sudo tee' per file
    )

    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        throw "ssh.exe not found on PATH. This needs the Windows OpenSSH Client optional feature " + `
            "(Settings -> Optional Features -> Add a feature -> OpenSSH Client, or " + `
            "'Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0' as admin)."
    }
    if (-not (Test-Path $SshKeyPath)) {
        throw "SSH private key not found: $SshKeyPath (see README.md for the one-time sudo+tee user setup this expects)."
    }

    $remoteDir = $RemoteDir.TrimEnd('/')
    # Matches the sudoers rule's own anchor exactly - see .DESCRIPTION for
    # why a looser check here would defeat the point of validating at all.
    $safeFilenamePattern = '^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$'

    foreach ($f in $LocalFiles) {
        if (-not (Test-Path $f)) { throw "File not found: $f" }
        $fileName = Split-Path $f -Leaf
        if ($fileName -notmatch $safeFilenamePattern) {
            throw "Refusing to upload '$fileName' over SSH: it doesn't match the safe filename pattern " + `
                "the node's sudoers rule expects ($safeFilenamePattern). This should never happen with " + `
                "this module's own generated snippet names - if you see this, something upstream built an " + `
                "unexpected filename."
        }
    }

    foreach ($f in $LocalFiles) {
        $fileName = Split-Path $f -Leaf
        $remotePath = "$remoteDir/$fileName"
        $remoteCmd = 'sudo tee "{0}" > /dev/null' -f $remotePath

        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        try {
            $sshArgs = @(
                '-i', $SshKeyPath,
                '-p', $SshPort,
                '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'BatchMode=yes',
                "$SshUser@$SshHost",
                $remoteCmd
            )
            $proc = Start-Process -FilePath 'ssh' -ArgumentList $sshArgs -NoNewWindow -Wait -PassThru `
                -RedirectStandardInput $f -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile

            if ($proc.ExitCode -ne 0) {
                $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
                $stderr = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                throw "ssh upload of '$fileName' to ${SshUser}@${SshHost}:${SshPort} failed (exit $($proc.ExitCode)):`n$stdout$stderr"
            }
        }
        finally {
            Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# UAG-specific deployment logic
# ---------------------------------------------------------------------------

function New-UagVmOnProxmox {
    <#
    .SYNOPSIS
        Creates (or cleanly rebuilds) one UAG VM on Proxmox purely via the
        REST API, by CLONING a template prepared once with
        New-UagProxmoxTemplate - no SSH/qm CLI involved, and no raw
        filesystem path touched at deploy time.

    .PARAMETER Context
        A plain API-token context (New-ProxmoxApiContext) is enough here -
        clone is a normal, ACL-respecting operation, unlike the
        import-from used by New-UagProxmoxTemplate's one-time setup. A
        ticket context also works if you happen to pass one, but there's
        no reason to use root credentials for routine deployments any
        more.

    .PARAMETER Platform
        The parsed [Platform] section from the unified INI (a hashtable),
        as returned by uagdeploy.psm1's ImportIni - see uagdeploypve.ps1.
        Must include 'templateVmid' (from a prior New-UagProxmoxTemplate
        run) instead of the old 'qcow2Image' field - qcow2Image is only
        relevant to that one-time setup now.

    .PARAMETER Smbios
        The parsed [Smbios] section, or $null to fall back to the
        validated defaults (Nutanix / AHV / 1.0). Re-applied explicitly
        after the clone even though the template already carries some
        value, so a deploy-time override always wins.

    .PARAMETER UserDataPath / MetaDataPath
        Paths to the already-generated uag-userdata.wrapped.yaml /
        uag-metadata.yaml (produced by Get-UagUserData.ps1 - this function
        only ships them to Proxmox, it does not build the payload itself).
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [hashtable]$Platform,
        [hashtable]$Smbios,
        [Parameter(Mandatory)] [string]$UserDataPath,
        [Parameter(Mandatory)] [string]$MetaDataPath,
        # Only meaningful when [Platform].vmid is set explicitly. A VMID
        # you pick by hand might already be in use by something unrelated
        # to this deployment (a typo, a shared/multi-user host) - without
        # -Force, an in-use explicit VMID is a hard error rather than
        # being silently stopped and destroyed. Not needed for the
        # auto-assigned case (no 'vmid' in [Platform]), which always gets
        # a fresh ID from /cluster/nextid and never collides.
        [switch]$Force
    )

    if (-not (Test-Path $UserDataPath)) { throw "User-data file not found: $UserDataPath" }
    if (-not (Test-Path $MetaDataPath)) { throw "Meta-data file not found: $MetaDataPath" }
    if (-not $Platform.node) { throw "[Platform] section is missing 'node'." }
    if (-not $Platform.storage) { throw "[Platform] section is missing 'storage'." }
    if (-not $Platform.bridge) { throw "[Platform] section is missing 'bridge'." }
    if (-not $Platform.templateVmid) {
        throw "[Platform] section is missing 'templateVmid'. Run New-UagPveTemplate.ps1 once " + `
            "to build a template from your golden QCOW2, then put the VMID it prints here."
    }
    if (-not $Platform.name) { throw "[Platform]/[General] is missing 'name' (used for the VM name and snippet filenames)." }
    if (-not $Platform.snippetSshUser -or -not $Platform.snippetSshKeyPath) {
        throw "[Platform] section is missing 'snippetSshUser' and/or 'snippetSshKeyPath'. Proxmox's API " + `
            "cannot upload cloud-init snippets at all, so this needs a one-time-created, non-root user " + `
            "with a scoped 'sudo tee' rule on the target node - see README.md for the setup steps, then " + `
            "put its username and your private key's local path here."
    }

    $node           = $Platform.node
    $storage        = $Platform.storage
    $snippetStorage = if ($Platform.snippetStorage) { $Platform.snippetStorage } else { $Platform.storage }
    $bridge         = $Platform.bridge
    $memoryMB       = if ($Platform.memoryMB) { [int]$Platform.memoryMB } else { 4096 }
    $cores          = if ($Platform.cores) { [int]$Platform.cores } else { 2 }
    $templateVmid   = [int]$Platform.templateVmid
    $sshHost        = if ($Platform.sshHost) { $Platform.sshHost } else { $Platform.host }
    $sshPort        = if ($Platform.snippetSshPort) { [int]$Platform.snippetSshPort } else { 22 }

    $vmid = Resolve-ProxmoxVmid -Context $Context -Node $node -ExplicitVmid $Platform.vmid -Force:$Force
    $vmidSource = if ($Platform.vmid) { '' } else { ' (auto-assigned via /cluster/nextid)' }
    Write-Host "Using VMID $vmid$vmidSource (cloning from template $templateVmid)"

    $smbios1Value = Get-UagSmbios1Value -Smbios $Smbios

    # --- Step 1: clone the prepared template ---------------------------------
    # full=1 makes this an independent full copy of the template's disk
    # (not a linked clone tied to the template's lifetime) - deliberate,
    # since UAG appliances are meant to be standalone and a linked clone
    # would keep every deployed instance dependent on the template
    # VM/disk never being deleted or resized. 'storage' pins the clone's
    # disk to this deployment's target storage rather than wherever the
    # template happens to live.
    $cloneBody = @{
        newid   = $vmid
        name    = $Platform.name
        target  = $node
        full    = 1
        storage = $storage
    }
    Write-Host '== 1/4: Cloning VM from template (full clone - may take a while for a large image) =='
    $cloneResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$node/qemu/$templateVmid/clone" -Method POST -Body $cloneBody
    if ($cloneResult.data) { Wait-ProxmoxTask -Context $Context -Node $node -Upid $cloneResult.data -TimeoutSec 1800 }

    # --- Step 2: per-deployment hardware + cloud-init drive -------------------
    # The template's own net0/memory/cores/smbios1 are just placeholders
    # (or whatever the template happened to be built with) - every actual
    # deployment reconfigures them explicitly here so [Platform] in the
    # INI is always the source of truth, not whatever the template carries.
    # ide2 (the cloud-init drive) is not part of the template at all - add
    # it fresh on every clone.
    Write-Host '== 2/4: Reconfiguring network/memory/cores/smbios + adding cloud-init drive =='
    $configBody = @{
        net0    = "virtio,bridge=$bridge"
        memory  = $memoryMB
        cores   = $cores
        smbios1 = $smbios1Value
        ide2    = "${storage}:cloudinit"
    }
    $cfgResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$node/qemu/$vmid/config" -Method PUT -Body $configBody
    if ($cfgResult.data) { Wait-ProxmoxTask -Context $Context -Node $node -Upid $cfgResult.data }

    # --- Step 3: deliver + attach the meta/user cloud-init snippets ---------
    # Proxmox's API has never supported uploading snippets (see
    # Send-UagSnippetsOverSsh's own header) - delivered over SSH to a
    # dedicated, non-root user with a scoped 'sudo tee' rule instead, the
    # same approach the bpg/terraform-provider-proxmox provider uses for
    # the identical gap. The API is not involved in this step at all.
    #
    # The remote filename comes from each local temp file's own name - so
    # stage temp copies under the exact intended snippet names first. The
    # remote directory is resolved from Proxmox's own storage config
    # rather than hardcoded or configured separately, so it can never
    # drift out of sync with whatever snippetStorage actually points at.
    Write-Host '== 3/4: Delivering meta/user-data snippets over SSH (sudo+tee - Proxmox has no API for this) =='
    $userSnippetName = "uag-$($Platform.name)-user.yaml"
    $metaSnippetName = "uag-$($Platform.name)-meta.yaml"

    $snippetStoragePath = Get-ProxmoxStoragePath -Context $Context -Storage $snippetStorage
    $remoteSnippetDir = "$snippetStoragePath/snippets"

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "uag-snippets-$vmid"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $userSnippetTemp = Join-Path $tempDir $userSnippetName
    $metaSnippetTemp = Join-Path $tempDir $metaSnippetName
    try {
        Copy-Item $UserDataPath $userSnippetTemp -Force
        Copy-Item $MetaDataPath $metaSnippetTemp -Force

        Send-UagSnippetsOverSsh -SshHost $sshHost -SshUser $Platform.snippetSshUser `
            -SshKeyPath $Platform.snippetSshKeyPath -SshPort $sshPort -RemoteDir $remoteSnippetDir `
            -LocalFiles @($userSnippetTemp, $metaSnippetTemp)
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    $cicustom = "meta=${snippetStorage}:snippets/$metaSnippetName,user=${snippetStorage}:snippets/$userSnippetName"
    $cicustomResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$node/qemu/$vmid/config" -Method PUT -Body @{ cicustom = $cicustom }
    if ($cicustomResult.data) { Wait-ProxmoxTask -Context $Context -Node $node -Upid $cicustomResult.data }

    # --- Step 4: start --------------------------------------------------------
    Write-Host "== 4/4: Starting VM $vmid =="
    $startResult = Invoke-ProxmoxApi -Context $Context -Path "/nodes/$node/qemu/$vmid/status/start" -Method POST
    if ($startResult.data) { Wait-ProxmoxTask -Context $Context -Node $node -Upid $startResult.data }

    Write-Host ''
    Write-Host "Done. VMID $vmid started. Wait roughly 1-2 minutes after the login prompt appears"
    Write-Host 'before testing SSH/admin UI (uag_sysconfig keeps running in the background for a'
    Write-Host 'while after the visible login prompt). Verify with:'
    Write-Host '  ssh root@<VM-IP> "dmesg | grep -i nutanix"'
    Write-Host '  ssh root@<VM-IP> "tail -30 /opt/omnissa/gateway/logs/vami.log"'

    return $vmid
}

Export-ModuleMember -Function `
    New-ProxmoxApiContext, `
    New-ProxmoxTicketContext, `
    Invoke-ProxmoxApi, `
    Send-ProxmoxFileUpload, `
    Send-ProxmoxImportUpload, `
    Get-ProxmoxStoragePath, `
    Send-UagSnippetsOverSsh, `
    Wait-ProxmoxTask, `
    Get-ProxmoxNextVmid, `
    Test-ProxmoxVmidInUse, `
    Resolve-ProxmoxVmid, `
    New-UagProxmoxTemplate, `
    New-UagVmOnProxmox
