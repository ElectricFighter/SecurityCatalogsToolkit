<#
.SYNOPSIS
    Enumerate the contents of a Windows security catalog (.cat): catalog-level
    attributes, and every member with its reference tag/hash, filename, and
    (optionally) per-member attributes such as File and OSAttr.

.DESCRIPTION
    Uses the wintrust.dll CryptCAT* enumeration APIs. Read-only; it opens the
    catalog with CRYPTCAT_OPEN_EXISTING and never modifies the store.
    Pair with Get-AuthenticodeSignature to see who signed the catalog.

.EXAMPLE
    .\Inspect-Catalog.ps1 -Path .\fsquirt-kb.cat

.EXAMPLE
    # include every attribute on every member (verbose)
    .\Inspect-Catalog.ps1 -Path .\fsquirt-kb.cat -Attributes

.NOTES
    Windows PowerShell 5.1. Test on a VM/snapshot as with anything catalog-related.

.PARAMETER Help
    Show detailed help (Get-Help -Detailed) and exit. Usage: .\Inspect-Catalog.ps1 -Help
#>

[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Run', Position = 0)]
    [string]$Path,

    # also dump every attribute of every member (File, OSAttr, etc.)
    [Parameter(ParameterSetName = 'Run')]
    [switch]$Attributes,

    # Show detailed help and exit.
    [Parameter(Mandatory, ParameterSetName = 'Help')]
    [switch]$Help
)

if ($Help) { Get-Help $PSCommandPath -Detailed; return }

if (-not (Test-Path $Path)) { throw "Catalog not found: $Path" }
$full = (Resolve-Path $Path).Path

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CryptCat {
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CryptCATOpen(string pwszFileName, uint fdwOpenFlags,
        IntPtr hProv, uint dwPublicVersion, uint dwEncodingType);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern bool CryptCATClose(IntPtr hCatalog);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr pPrevMember);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern IntPtr CryptCATEnumerateAttr(IntPtr hCatalog, IntPtr pCatMember, IntPtr pPrevAttr);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern IntPtr CryptCATEnumerateCatAttr(IntPtr hCatalog, IntPtr pPrevAttr);

    // Only the leading fields are read; the trailing blobs keep the layout/offsets correct.
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPTCATMEMBER {
        public uint  cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszReferenceTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszFileName;
        public Guid  gSubjectType;
        public uint  fdwMemberFlags;
        public IntPtr pIndirectData;
        public uint  fdwCertVersion;
        public uint  dwReserved;
        public IntPtr hReserved;
        public uint  eid_cbData;  public IntPtr eid_pbData;   // sEncodedIndirectData
        public uint  emi_cbData;  public IntPtr emi_pbData;   // sEncodedMemberInfo
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPTCATATTRIBUTE {
        public uint  cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszReferenceTag;
        public uint  dwAttrTypeAndAction;
        public uint  cbValue;
        public IntPtr pbValue;
        public uint  dwReserved;
    }
}
"@

$CRYPTCAT_OPEN_EXISTING = 0x2

function Read-AttrValue($a) {
    if ($a.pbValue -eq [IntPtr]::Zero -or $a.cbValue -eq 0) { return $null }
    # File / OSAttr / etc. are stored as null-terminated Unicode strings
    $s = $null
    try { $s = [Runtime.InteropServices.Marshal]::PtrToStringUni($a.pbValue) } catch { }
    if ($s -and ($s -match '^[\x20-\x7E]*$')) { return $s }
    # otherwise show raw bytes
    $bytes = New-Object byte[] $a.cbValue
    [Runtime.InteropServices.Marshal]::Copy($a.pbValue, $bytes, 0, [int]$a.cbValue)
    return [BitConverter]::ToString($bytes)
}

$mType = [CryptCat+CRYPTCATMEMBER]
$aType = [CryptCat+CRYPTCATATTRIBUTE]

# PowerShell can bind [Marshal]::PtrToStructure($ptr,$type) to the wrong overload
# (IntPtr, object) and fail with "must be blittable or have layout information".
# Grab the generic PtrToStructure<T>(IntPtr) once and invoke it explicitly instead.
# Works on Windows PowerShell 5.1 and all PowerShell 7.x.
$script:PtsGeneric = [Runtime.InteropServices.Marshal].GetMethods() |
    Where-Object { $_.Name -eq 'PtrToStructure' -and $_.IsGenericMethodDefinition -and
                   $_.GetParameters().Count -eq 1 -and
                   $_.GetParameters()[0].ParameterType -eq [IntPtr] } |
    Select-Object -First 1

function ConvertTo-Struct {
    param([IntPtr]$Ptr, [Type]$Type)
    $script:PtsGeneric.MakeGenericMethod($Type).Invoke($null, @([Object]$Ptr))
}

$h = [CryptCat]::CryptCATOpen($full, $CRYPTCAT_OPEN_EXISTING, [IntPtr]::Zero, 0, 0)
if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) {
    throw "CryptCATOpen failed (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))."
}

try {
    Write-Host "Catalog: $full`n" -ForegroundColor Cyan

    Write-Host "-- catalog-level attributes --" -ForegroundColor Cyan
    $pa = [IntPtr]::Zero
    while (($pa = [CryptCat]::CryptCATEnumerateCatAttr($h, $pa)) -ne [IntPtr]::Zero) {
        $a = ConvertTo-Struct $pa $aType
        "  {0} = {1}" -f $a.pwszReferenceTag, (Read-AttrValue $a)
    }

    Write-Host "`n-- members --" -ForegroundColor Cyan
    $count = 0
    $pm = [IntPtr]::Zero
    while (($pm = [CryptCat]::CryptCATEnumerateMember($h, $pm)) -ne [IntPtr]::Zero) {
        $m = ConvertTo-Struct $pm $mType
        $count++
        "[{0}] tag/hash: {1}" -f $count, $m.pwszReferenceTag
        if ($m.pwszFileName) { "       file: {0}" -f $m.pwszFileName }
        if ($Attributes) {
            $paM = [IntPtr]::Zero
            while (($paM = [CryptCat]::CryptCATEnumerateAttr($h, $pm, $paM)) -ne [IntPtr]::Zero) {
                $am = ConvertTo-Struct $paM $aType
                "         {0} = {1}" -f $am.pwszReferenceTag, (Read-AttrValue $am)
            }
        }
    }
    Write-Host "`n$count member(s) total." -ForegroundColor Green
}
finally {
    [CryptCat]::CryptCATClose($h) | Out-Null
}
