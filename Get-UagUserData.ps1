# Get-UagUserData.ps1
# -----------------------------------------------------------------------
# Produces UAG's own cloud-init "user-data" payload from a regular UAG INI
# file, for platforms without a ready-made uagdeploy*.ps1 of their own
# (Proxmox, libvirt, Unraid, generic KVM).
#
# Field names (DNS, rootPasswordExpirationDays, sshEnabled, ...) are UAG's
# own documented cloud-init interface, not invented here. How this script
# builds and emits them is this project's own code.
#
# This script calls a number of *exported* helper functions from Omnissa's
# own uagdeploy.psm1 (ImportIni, GetJSONSettings, ReadOsLoginUsername,
# validators) through that module's public API, the same way uagdeploy.ps1
# does for the officially supported platforms. uagdeploy.psm1 is Omnissa's
# own copyrighted software, not included or redistributed here; obtain it
# through your own Omnissa/VMware entitlement and place it alongside this
# script (see README.md).
#
# Examples:
#   pwsh ./Get-UagUserData.ps1 -IniFile your-instance.ini -RootPwd 'M3inRoot!Pwd' -AdminPwd 'M3inAdmin!Pwd'
#   pwsh ./Get-UagUserData.ps1 -IniFile your-instance.ini -RootPwd 'M3inRoot!Pwd' -NoStaticIpFields
#
# Produces in the current directory:
#   uag-userdata.raw.txt      -> unwrapped plain text (as used by OpenStack)
#   uag-userdata.wrapped.yaml -> wrapped as #cloud-config/write_files (as used by Nutanix/KubeVirt)
#   uag-userdata.raw.b64 / uag-userdata.wrapped.b64 -> base64 versions of each
#   uag-metadata.yaml         -> minimal NoCloud meta-data file
# -----------------------------------------------------------------------

param(
    [Parameter(Mandatory = $true)] [string]$IniFile,
    [string]$RootPwd = "ChangeMe-Root-123!",
    [string]$AdminPwd = "ChangeMe-Admin-123!",
    [bool]$CeipEnabled = $true,
    [switch]$NoStaticIpFields,   # omit if IP should instead be handled via cloud-init network-config/DHCP
    [string]$InstanceId = "uag-test-01",
    [string]$Hostname = "uag-test-01"
)

$ModuleDir = Split-Path -Parent (Resolve-Path $PSCommandPath)
$ModulePath = Join-Path $ModuleDir "uagdeploy.psm1"
if (!(Test-Path $ModulePath)) {
    Write-Error "uagdeploy.psm1 not found in $ModuleDir. Obtain it from your own Omnissa entitlement and place it in the same folder as this script."
    exit 1
}
Import-Module $ModulePath -Force

function Get-UagNicCount {
    # UAG's own deploymentOption values encode the NIC count in their
    # leading token (onenic / twonic / threenic, optionally followed by
    # "-..." qualifiers such as certificate or syslog options). Those
    # prefixes are fixed by UAG's own documented deployment options.
    param([string]$DeploymentOption)

    switch -Regex ($DeploymentOption) {
        '^onenic'   { return 1 }
        '^twonic'   { return 2 }
        '^threenic' { return 3 }
        default     { return 0 }
    }
}

function Build-UagStaticIpFields {
    # For each NIC, emits ipModeN always, and ipN/netmaskN only when that
    # NIC is statically addressed. Falls back to DHCPV4 when no ipModeN is
    # set in the INI and no ipN is given either.
    param($Settings, $DeploymentOption)

    $nicCount = Get-UagNicCount -DeploymentOption $DeploymentOption
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $nicCount; $i++) {
        $ipModeKey = "ipMode$i"; $ipKey = "ip$i"; $netmaskKey = "netmask$i"
        $ipMode = $Settings.General.$ipModeKey
        $ip = $Settings.General.$ipKey
        $netmask = $Settings.General.$netmaskKey

        if ([string]::IsNullOrEmpty($ipMode)) {
            $ipMode = if ([string]::IsNullOrEmpty($ip)) { 'DHCPV4' } else { 'STATICV4' }
        }

        [void]$sb.Append("$ipModeKey=$ipMode`n")
        if ($ipMode -like '*STATIC*') {
            [void]$sb.Append("$ipKey=$ip`n")
            [void]$sb.Append("$netmaskKey=$netmask`n")
        }
    }
    return $sb.ToString()
}

function Format-UagUserDataIndent {
    # cloud-init's YAML block-scalar syntax ("content: |") requires every
    # embedded line to sit at a deeper indentation than the "content:" key
    # itself - 6 spaces here, to nest under the 4-space "path:"/"content:"
    # block below. This is a YAML syntax requirement, not a style choice.
    param([string]$RawContent)

    return ($RawContent -split "`n" |
        Where-Object { $_.Trim().Length -gt 0 } |
        ForEach-Object { "      $_" }) -join "`n"
}

function ConvertTo-UagCloudInitWrapper {
    # Wraps a raw UAG user-data payload in a minimal cloud-config
    # write_files stanza. The target path is NOT a free choice here - it
    # has to be exactly /var/lib/cloud/instance/user-data.txt, the path
    # UAG's own firstboot script (uag_sysconfig, inside the appliance
    # itself) reads on generic-KVM platforms.
    param([string]$IndentedContent)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('#cloud-config')
    [void]$sb.AppendLine('write_files:')
    [void]$sb.AppendLine('  - path: /var/lib/cloud/instance/user-data.txt')
    [void]$sb.AppendLine('    content: |')
    [void]$sb.AppendLine($IndentedContent)
    [void]$sb.Append("    permissions: '0644'")
    return $sb.ToString()
}

# ---- read the INI file (via uagdeploy.psm1's own exported functions) ----
$settings = ImportIni $IniFile
$settingsJSON = GetJSONSettings $settings $null
$deploymentOption = GetDeploymentSettingOption $settings
$osLoginUsername = ReadOsLoginUsername $settings
if ($osLoginUsername.Length -eq 0) { $osLoginUsername = "root" }

# ---- UAG's documented user-data field set, in insertion order ----
# Values come either straight from the INI, or through uagdeploy.psm1's own
# exported validators (ValidateAdminMaxConcurrentSessions and similar) so
# validation behavior matches the officially supported platforms exactly.
$fields = [ordered]@{}
$fields['DNS'] = $settings.General.DNS
if ($osLoginUsername -ne 'root') { $fields['osLoginUsername'] = $osLoginUsername }
$fields['osMaxLoginLimit'] = ReadOsMaxLoginLimit $settings
$fields['rootPasswordExpirationDays'] = $settings.General.rootPasswordExpirationDays
$fields['passwordPolicyMinLen'] = $settings.General.passwordPolicyMinLen
$fields['passwordPolicyMinClass'] = $settings.General.passwordPolicyMinClass
$fields['passwordPolicyDifok'] = $settings.General.passwordPolicyDifok
$fields['passwordPolicyUnlockTime'] = $settings.General.passwordPolicyUnlockTime
$fields['passwordPolicyFailedLockout'] = $settings.General.passwordPolicyFailedLockout
$fields['adminPasswordPolicyFailedLockoutCount'] = $settings.General.adminPasswordPolicyFailedLockoutCount
$fields['adminPasswordPolicyMinLen'] = $settings.General.adminPasswordPolicyMinLen
$fields['adminPasswordPolicyUnlockTime'] = $settings.General.adminPasswordPolicyUnlockTime
$fields['adminSessionIdleTimeoutMinutes'] = $settings.General.adminSessionIdleTimeoutMinutes
$fields['adminMaxConcurrentSessions'] = ValidateAdminMaxConcurrentSessions $settings
$fields['rootSessionIdleTimeoutSeconds'] = ValidateRootSessionIdleTimeoutSeconds $settings
$fields['commandsFirstBoot'] = ValidateCustomBootTimeCommands $settings "commandsFirstBoot"
$fields['commandsEveryBoot'] = ValidateCustomBootTimeCommands $settings "commandsEveryBoot"
$fields['defaultGateway'] = $settings.General.defaultGateway
$fields['v6DefaultGateway'] = $settings.General.v6DefaultGateway
$fields['forwardrules'] = $settings.General.forwardrules
foreach ($idx in 0..2) { $fields["routes$idx"] = $settings.General."routes$idx" }
foreach ($idx in 0..2) { $fields["policyRouteGateway$idx"] = $settings.General."policyRouteGateway$idx" }
if ($CeipEnabled) { $fields['ceipEnabled'] = 'true' }
if ($settings.General.dsComplianceOS -eq 'true') { $fields['dsComplianceOS'] = 'true' }
if ($settings.General.tlsPortSharingEnabled -eq 'true') { $fields['tlsPortSharingEnabled'] = 'true' }
if ($settings.General.sshEnabled -eq 'true') { $fields['sshEnabled'] = 'true' }
if ($settings.General.sshPasswordAccessEnabled -eq 'false') { $fields['sshPasswordAccessEnabled'] = 'false' }
if ($settings.General.sshKeyAccessEnabled -eq 'true') { $fields['sshKeyAccessEnabled'] = 'true' }
$fields['sshLoginBannerText'] = ReadLoginBannerText $settings
$fields['sshInterface'] = validateSSHInterface $settings
if ($settings.General.sshPort -match '^[0-9]+$') { $fields['sshPort'] = $settings.General.sshPort }
$fields['secureRandomSource'] = ReadSecureRandomSource $settings
$fields['rootPassword'] = $RootPwd
if ($AdminPwd.Length -gt 0) { $fields['adminPassword'] = $AdminPwd }
$fields['enabledAdvancedFeatures'] = $settings.General.enabledAdvancedFeatures
$fields['gatewaySpec'] = getGatewaySpec $settings
$fields['configURL'] = $settings.General.configURL
$fields['configKey'] = $settings.General.configKey
$fields['configURLThumbprints'] = $settings.General.configURLThumbprints
$fields['configURLHttpProxy'] = $settings.General.configURLHttpProxy
$fields['adminCsrSubject'] = $settings.General.adminCsrSubject
$fields['adminCsrSAN'] = $settings.General.adminCsrSAN
$fields['additionalDeploymentMetadata'] = $settings.General.additionalDeploymentMetadata

# ---- emit "key=value" lines, in the order the fields were added above ----
$sb = [System.Text.StringBuilder]::new()
foreach ($key in $fields.Keys) {
    if ($key -eq 'rootPassword') {
        # rootPassword is always emitted, even if somehow empty - matches
        # the behavior validated live against a real UAG boot.
        [void]$sb.Append("rootPassword=$($fields['rootPassword'])`n")
        continue
    }
    $value = $fields[$key]
    if ($null -ne $value -and "$value".Length -gt 0) {
        [void]$sb.Append("$key=$value`n")
    }
}
$userDataPayload = $sb.ToString()

if (-not $NoStaticIpFields) {
    $userDataPayload += Build-UagStaticIpFields -Settings $settings -DeploymentOption $deploymentOption
}
$userDataPayload += "settingsJSON=$settingsJSON"

# ---- output: both raw and wrapped, so both can be tested ----
$formatted = Format-UagUserDataIndent $userDataPayload
$wrapped = ConvertTo-UagCloudInitWrapper $formatted

$userDataPayload | Out-File -FilePath "./uag-userdata.raw.txt" -Encoding utf8NoBOM -NoNewline
$wrapped | Out-File -FilePath "./uag-userdata.wrapped.yaml" -Encoding utf8NoBOM -NoNewline
(stringToBase64($userDataPayload)) | Out-File -FilePath "./uag-userdata.raw.b64" -Encoding utf8NoBOM -NoNewline
(stringToBase64($wrapped)) | Out-File -FilePath "./uag-userdata.wrapped.b64" -Encoding utf8NoBOM -NoNewline

@"
instance-id: $InstanceId
local-hostname: $Hostname
"@ | Out-File -FilePath "./uag-metadata.yaml" -Encoding utf8NoBOM -NoNewline

Write-Host "Done. Files produced in the current directory:"
Write-Host "  uag-userdata.raw.txt / uag-userdata.raw.b64          (unwrapped, as used by OpenStack)"
Write-Host "  uag-userdata.wrapped.yaml / uag-userdata.wrapped.b64 (wrapped as #cloud-config, as used by Nutanix/KubeVirt)"
Write-Host "  uag-metadata.yaml                                    (NoCloud meta-data)"
Write-Host ""
Write-Host "Recommendation: start the first test with uag-userdata.wrapped.yaml as user-data (valid YAML,"
Write-Host "closest to the already-working production Nutanix/KubeVirt paths)."
