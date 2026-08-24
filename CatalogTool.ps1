<#
.SYNOPSIS
    List, add, or remove Windows security catalogs (.cat) in the system catalog store.

.DESCRIPTION
    Wraps the wintrust.dll CryptCATAdmin* APIs, which is exactly how Windows Update
    registers catalogs. Adding a catalog updates both the file store (CatRoot) and the
    catalog database (catroot2), so catalog-signed files start verifying immediately.

    System catalog store GUID (DRIVER_ACTION_VERIFY):
        {F750E6C3-38EE-11D1-85E5-00C04FC295EE}

.EXAMPLE
    .\CatalogTool.ps1 -Action List

.EXAMPLE
    .\CatalogTool.ps1 -Action Add -Catalog C:\extract\fsquirt-kb.cat -Name fsquirt-kb.cat

.EXAMPLE
    .\CatalogTool.ps1 -Action Remove -Catalog fsquirt-kb.cat

.NOTES
    Add and Remove modify the system catalog store and require an elevated (Administrator)
    PowerShell; the script checks and stops with a clear message if not elevated. List only
    reads CatRoot and works as a normal user. Test on a VM snapshot first.

.PARAMETER Help
    Show detailed help (Get-Help -Detailed) and exit. Usage: .\CatalogTool.ps1 -Help
#>

[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Run', Position = 0)]
    [ValidateSet('List', 'Add', 'Remove')]
    [string]$Action,

    # Add   -> full path to the .cat file
    # Remove-> the base name the catalog is stored under (as shown by -Action List)
    [Parameter(ParameterSetName = 'Run')]
    [string]$Catalog,

    # Optional: name to store the catalog under when adding (defaults to the file name)
    [Parameter(ParameterSetName = 'Run')]
    [string]$Name,

    # Show detailed help and exit.
    [Parameter(Mandatory, ParameterSetName = 'Help')]
    [switch]$Help
)

if ($Help) { Get-Help $PSCommandPath -Detailed; return }

$storeGuid = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$store     = Join-Path $env:SystemRoot "System32\CatRoot\$storeGuid"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CatApi {
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CryptCATAdminAcquireContext(ref IntPtr h, ref Guid sub, uint flags);

    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CryptCATAdminAddCatalog(IntPtr h, string cat, string baseName, uint flags);

    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr h, IntPtr info, uint flags);

    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CryptCATAdminRemoveCatalog(IntPtr h, string cat, uint reserved);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern bool CryptCATAdminReleaseContext(IntPtr h, uint flags);
}
"@

function LastErr { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Add/Remove modify the system catalog store and require elevation; fail fast with a clear
# message instead of a cryptic Win32 error (e.g. 5 = Access denied, 203 = env var not found).
if ($Action -in @('Add', 'Remove') -and -not (Test-Administrator)) {
    Write-Host ("'{0}' modifies the system catalog store and must run as Administrator." -f $Action) -ForegroundColor Yellow
    Write-Host "This PowerShell session is not elevated, so the operation would fail." -ForegroundColor Yellow
    Write-Host "Re-open PowerShell with 'Run as administrator' and run the same command again." -ForegroundColor Yellow
    return
}

function Get-CatAdminContext {
    $guid = [Guid]$storeGuid
    $h    = [IntPtr]::Zero
    if (-not [CatApi]::CryptCATAdminAcquireContext([ref]$h, [ref]$guid, 0)) {
        throw "CryptCATAdminAcquireContext failed (Win32 error $(LastErr)). Run elevated."
    }
    return $h
}

switch ($Action) {

    'List' {
        if (-not (Test-Path $store)) { throw "Catalog store not found: $store" }
        Get-ChildItem -Path (Join-Path $store '*.cat') -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object Name, Length, LastWriteTime
    }

    'Add' {
        if (-not $Catalog)            { throw "Pass -Catalog <path to .cat>." }
        if (-not (Test-Path $Catalog)){ throw "Catalog not found: $Catalog" }
        if (-not $Name)               { $Name = Split-Path $Catalog -Leaf }

        $full = (Resolve-Path $Catalog).Path
        $h = Get-CatAdminContext
        try {
            $info = [CatApi]::CryptCATAdminAddCatalog($h, $full, $Name, 0)
            if ($info -eq [IntPtr]::Zero) {
                throw "CryptCATAdminAddCatalog failed (Win32 error $(LastErr))."
            }
            [CatApi]::CryptCATAdminReleaseCatalogContext($h, $info, 0) | Out-Null
            Write-Host "Added catalog, stored as '$Name'." -ForegroundColor Green
        }
        finally {
            [CatApi]::CryptCATAdminReleaseContext($h, 0) | Out-Null
        }
    }

    'Remove' {
        if (-not $Catalog) { throw "Pass -Catalog <stored base name> (see -Action List)." }
        $h = Get-CatAdminContext
        try {
            if (-not [CatApi]::CryptCATAdminRemoveCatalog($h, $Catalog, 0)) {
                throw "CryptCATAdminRemoveCatalog failed (Win32 error $(LastErr))."
            }
            Write-Host "Removed catalog '$Catalog' from the store." -ForegroundColor Yellow
        }
        finally {
            [CatApi]::CryptCATAdminReleaseContext($h, 0) | Out-Null
        }
    }
}
