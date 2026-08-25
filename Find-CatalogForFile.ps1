<#
.SYNOPSIS
    Find which security catalog (.cat) inside a Windows update package (.msu/.cab)
    contains the signing entry for a given file (or a given catalog/Authenticode hash),
    and report the container that holds the matching payload.

.DESCRIPTION
    1. Computes the file's *catalog* hash with CryptCATAdminCalcHashFromFileHandle2 --
       the exact function Windows uses to look a file up in the catalog store, so it
       returns the Authenticode hash for PE files (NOT the flat Get-FileHash value).
    2. Extracts the package with expand.exe, following nested cabs. By default it does a
       fast "catalogs-only" pass: it pulls ONLY cabs and .cat files and leaves the payload
       compressed. Pass -FullExtract to expand every file instead.
    3. Searches every extracted .cat for the raw digest bytes (stored in each member's
       SPC_INDIRECT_DATA). For each match (in BOTH -File and -Hash mode) it COPIES the
       catalog out to -OutDir, and reports the full location of both the catalog and its
       payload *as paths within the original package*, with copy-paste expand recipes, so
       either can be re-extracted manually later straight from the original .msu.

    The temp work folder is deleted at the end unless -KeepFiles is given; the delivered
    catalog and the reported recipes never depend on it.

    Use -File to let the script compute the right hash (recommended), or -Hash to pass one
    you already have. If you pass -Hash it MUST be the Authenticode/catalog hash for PE
    files, not a flat file hash.

.PARAMETER FullExtract
    Expand the entire package (every file), not just cabs + catalogs. Slower, but the
    payload lands on disk so you don't need a second manual extraction step.

.PARAMETER OutDir
    Folder the matching catalog(s) are copied into. Defaults to .\matched-catalogs.
    Pass -OutDir '' to skip copying and only report locations.

.PARAMETER SearchThreads
    Search catalogs in parallel with this many threads (PowerShell 7+). Default 1 (serial).
    Helps most with -FullExtract or packages with many/large catalogs.

.EXAMPLE
    # default: fast, catalogs-only, no fallback
    .\Find-CatalogForFile.ps1 -Package .\windows10.0-kb5000000-x64.msu -File C:\extract\fsquirt.exe

.EXAMPLE
    # expand everything and search 8-wide
    .\Find-CatalogForFile.ps1 -Package .\update.cab -Hash 92894DD5...BC29E3 -FullExtract -SearchThreads 8

.NOTES
    Run elevated on Windows. expand.exe must be on PATH (it is by default).
    Newest differential (PSF) updates may not expose catalogs via expand.exe; if nothing is
    found, fall back to the CatRoot before/after diff on a serviced image.

.PARAMETER Help
    Show detailed help (Get-Help -Detailed) and exit. Usage: .\Find-CatalogForFile.ps1 -Help
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory, ParameterSetName = 'File')]
    [Parameter(Mandatory, ParameterSetName = 'Hash')]
    [string]$Package,

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string]$File,

    [Parameter(Mandatory, ParameterSetName = 'Hash')]
    [string]$Hash,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Hash')]
    [string]$WorkDir,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Hash')]
    [switch]$KeepFiles,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Hash')]
    [switch]$FullExtract,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Hash')]
    [int]$SearchThreads = 1,

    # Where to copy the matching catalog(s) so they survive cleanup and are easy to install.
    # Defaults to .\matched-catalogs. Pass -OutDir '' to skip copying.
    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Hash')]
    [string]$OutDir = (Join-Path (Get-Location) 'matched-catalogs'),

    # Show detailed help and exit.
    [Parameter(Mandatory, ParameterSetName = 'Help')]
    [switch]$Help
)

if ($Help) { Get-Help $PSCommandPath -Detailed; return }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CatHash {
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CryptCATAdminAcquireContext2(
        ref IntPtr phCatAdmin, ref Guid pgSubsystem, string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError=true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
}
"@

$DRIVER_ACTION_VERIFY = [Guid]'{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'

function Get-CatalogHash {
    param([string]$Path, [string]$Algorithm)  # 'SHA256' or 'SHA1'
    $len  = if ($Algorithm -eq 'SHA1') { 20 } else { 32 }
    $hCat = [IntPtr]::Zero
    $guid = $DRIVER_ACTION_VERIFY
    if (-not [CatHash]::CryptCATAdminAcquireContext2([ref]$hCat, [ref]$guid, $Algorithm, [IntPtr]::Zero, 0)) {
        return $null
    }
    try {
        $fs = [IO.File]::Open((Resolve-Path $Path).Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $handle = $fs.SafeFileHandle.DangerousGetHandle()
            $cb  = [uint32]$len
            $buf = New-Object byte[] $len
            if (-not [CatHash]::CryptCATAdminCalcHashFromFileHandle2($hCat, $handle, [ref]$cb, $buf, 0)) {
                throw "CalcHash failed (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))."
            }
            return $buf
        } finally { $fs.Dispose() }
    } finally { [CatHash]::CryptCATAdminReleaseContext($hCat, 0) | Out-Null }
}

function Convert-HexToBytes {
    param([string]$Hex)
    $Hex = ($Hex -replace '(?i)^sha\d+\s*', '') -replace '0x', '' -replace '[\s:-]', ''
    if ($Hex.Length % 2) { throw "Hex string has odd length." }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

# byte-subsequence search (fast path via IndexOf on the first byte)
function Test-Contains {
    param([byte[]]$Data, [byte[]]$Pattern)
    $n = $Data.Length; $m = $Pattern.Length
    if ($m -eq 0 -or $m -gt $n) { return $false }
    $first = $Pattern[0]
    $i = [Array]::IndexOf($Data, $first, 0)
    while ($i -ge 0 -and $i -le ($n - $m)) {
        $j = 1
        while ($j -lt $m -and $Data[$i + $j] -eq $Pattern[$j]) { $j++ }
        if ($j -eq $m) { return $true }
        $i = [Array]::IndexOf($Data, $first, $i + 1)
    }
    return $false
}

# Expand recursively. $Origin maps extractedFilePath -> containerPath, and $Inner maps
# extractedFilePath -> its path *inside* that container, so a match can be traced all the
# way back to the original package as a reproducible expand recipe.
#
# Loop protection: dedup by CONTENT (name + size), not path, because every extraction lands
# in a fresh folder so paths are always new. Cabs like constraintindex.cab can contain a
# same-named cab (or the same cab is reached via two routes); without content dedup that
# recurses forever. A depth cap and a self-reference guard are belt-and-suspenders, and the
# WSUS index cabs (which never hold catalogs) are skipped outright.
function Expand-Package {
    param(
        [string]$Source,
        [string]$Root,
        [bool]$Full,
        [hashtable]$Origin,
        [hashtable]$Inner,
        [int]$MaxDepth = 16
    )
    $ignore = @('constraintindex.cab', 'wsusscan.cab', 'wsusscan.cab.txt')
    function Sig([string]$Path) {
        $fi = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if (-not $fi) { return $null }
        return ('{0}|{1}' -f $fi.Name.ToLowerInvariant(), $fi.Length)
    }
    function FileHash([string]$Path) {
        try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { return $null }
    }

    # $seen maps a name+size signature to the set of content hashes actually processed for it.
    # name+size is only a pre-filter: the first time a signature repeats we hash to CONFIRM the
    # bytes match before skipping, so a real collision (same name+size, different content) is
    # still processed instead of being silently dropped. Hashing is lazy -- a signature that
    # never repeats (the common case, and big cabs) is never hashed.
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $seen  = @{}
    $queue.Enqueue([pscustomobject]@{ Path = (Resolve-Path $Source).Path; Depth = 0 })
    $pkgCount = 0
    $skipped  = 0

    while ($queue.Count -gt 0) {
        $item  = $queue.Dequeue()
        $pkg   = $item.Path
        $depth = $item.Depth
        $name  = [IO.Path]::GetFileName($pkg)

        if ($ignore -contains $name.ToLowerInvariant()) { $skipped++; continue }
        $sig = Sig $pkg
        if ($null -eq $sig) { $skipped++; continue }

        if (-not $seen.ContainsKey($sig)) {
            # first container with this name+size: register it, defer hashing until/unless it repeats
            $seen[$sig] = [pscustomobject]@{ FirstPath = $pkg; Hashes = @{}; FirstHashed = $false }
        } else {
            # name+size repeats: confirm by content hash before deciding to skip
            $entry = $seen[$sig]
            if (-not $entry.FirstHashed) {
                $fh = FileHash $entry.FirstPath
                if ($fh) { $entry.Hashes[$fh] = $true }
                $entry.FirstHashed = $true
            }
            $curHash = FileHash $pkg
            if ($null -ne $curHash -and $entry.Hashes.ContainsKey($curHash)) {
                $skipped++; continue                                  # confirmed identical bytes -> skip
            }
            if ($null -ne $curHash) { $entry.Hashes[$curHash] = $true }
            Write-Host ("  [~] name+size collision on {0}; content differs -- processing it too" -f $name) -ForegroundColor DarkYellow
        }

        if ($depth -gt $MaxDepth) {
            Write-Host ("  [!] depth limit ({0}) reached at {1}; not descending further" -f $MaxDepth, $name) -ForegroundColor Yellow
            continue
        }

        $pkgCount++
        Write-Host ("  [{0}] expanding {1} ..." -f $pkgCount, $name) -ForegroundColor DarkGray -NoNewline
        Write-Progress -Activity 'Expanding package' -Status ("$name  ($($queue.Count) still queued)")

        $out = Join-Path $Root ($name + '.' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Force -Path $out | Out-Null

        if ($Full) {
            & expand.exe -f:* "$pkg" "$out" 2>$null | Out-Null
        } else {
            foreach ($flt in '*.cab', '*.msu', '*.cat') {
                & expand.exe -F:$flt "$pkg" "$out" 2>$null | Out-Null
            }
        }

        $extracted = @(Get-ChildItem -Path $out -Recurse -File -ErrorAction SilentlyContinue)
        foreach ($f in $extracted) {
            $Origin[$f.FullName] = $pkg
            $Inner[$f.FullName]  = $f.FullName.Substring($out.Length).TrimStart('\', '/')
        }

        # enqueue nested containers; content dedup happens at dequeue so collisions still get through
        $catsHere = @($extracted | Where-Object { $_.Extension -eq '.cat' })
        $nested   = @($extracted | Where-Object {
            $_.Extension -in @('.cab', '.msu') -and ($ignore -notcontains $_.Name.ToLowerInvariant())
        })
        foreach ($n in $nested) { $queue.Enqueue([pscustomobject]@{ Path = $n.FullName; Depth = $depth + 1 }) }

        Write-Host ("  {0} files, {1} .cat, {2} nested  ->  {3} queued" -f `
            $extracted.Count, $catsHere.Count, $nested.Count, $queue.Count) -ForegroundColor DarkGray
    }
    Write-Progress -Activity 'Expanding package' -Completed
    if ($skipped) { Write-Host ("  ({0} duplicate/index container(s) skipped)" -f $skipped) -ForegroundColor DarkGray }
    return $pkgCount
}

function Search-Catalogs {
    param([System.IO.FileInfo[]]$Cats, [Object[]]$Needles, [int]$SearchThreads)
    $total = $Cats.Count
    if ($total -eq 0) { return @() }

    if ($SearchThreads -gt 1 -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host ("Scanning {0} catalogs across up to {1} threads...`n" -f $total, $SearchThreads)
        $bag = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
        $Cats | ForEach-Object -ThrottleLimit $SearchThreads -Parallel {
            $needles = $using:Needles
            $bag     = $using:bag
            $data    = [IO.File]::ReadAllBytes($_.FullName)
            foreach ($pat in $needles) {
                $n = $data.Length; $m = $pat.Length
                if ($m -eq 0 -or $m -gt $n) { continue }
                $first = $pat[0]; $i = [Array]::IndexOf($data, $first, 0); $hit = $false
                while ($i -ge 0 -and $i -le ($n - $m)) {
                    $j = 1
                    while ($j -lt $m -and $data[$i + $j] -eq $pat[$j]) { $j++ }
                    if ($j -eq $m) { $hit = $true; break }
                    $i = [Array]::IndexOf($data, $first, $i + 1)
                }
                if ($hit) { $bag.Add($_.FullName); break }
            }
        }
        $found = @($bag) | Sort-Object -Unique
        foreach ($f in $found) { Write-Host ("  [+] match in {0}" -f [IO.Path]::GetFileName($f)) -ForegroundColor Green }
        return $found
    }

    # serial with live progress
    if ($SearchThreads -gt 1) { Write-Host "(-SearchThreads needs PowerShell 7+; running serially.)`n" -ForegroundColor Yellow }
    $scanned = 0; $matchCount = 0; $found = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($cat in $Cats) {
        $scanned++
        Write-Progress -Activity 'Searching catalogs' `
            -Status ("{0}/{1}  matches: {2}  |  {3}" -f $scanned, $total, $matchCount, $cat.Name) `
            -PercentComplete ([int](100 * $scanned / $total))
        $bytes = [IO.File]::ReadAllBytes($cat.FullName)
        foreach ($needle in $Needles) {
            if (Test-Contains -Data $bytes -Pattern $needle) {
                $found += $cat.FullName; $matchCount++
                Write-Host ("  [+] match in {0}" -f $cat.Name) -ForegroundColor Green
                break
            }
        }
        if ($scanned % 25 -eq 0 -or $scanned -eq $total) {
            Write-Host ("  ... {0}/{1} scanned ({2:n0}s)" -f $scanned, $total, $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        }
    }
    Write-Progress -Activity 'Searching catalogs' -Completed
    return $found
}

# Walk the parent chain to build the ordered list of leaf names to expand,
# from the original package down to (and including) $FilePath.
function Get-ExtractChain {
    param([string]$FilePath, [hashtable]$Origin, [hashtable]$Inner)
    $names = New-Object System.Collections.Generic.List[string]
    $cur = $FilePath
    while ($Origin.ContainsKey($cur)) {
        $names.Insert(0, [IO.Path]::GetFileName($Inner[$cur]))
        $cur = $Origin[$cur]
    }
    foreach ($n in $names) { $n }   # emit each leaf; caller collects with @() -> flat string[]
}

# Render a copy-paste expand recipe from the original package. $Steps is the ordered
# list of leaf names; the last one is the file being extracted, earlier ones are cabs.
function Format-Recipe {
    param([string[]]$Steps, [string]$Original, [string]$FinalDest)
    $lines = @()
    $src = '"{0}"' -f $Original
    for ($i = 0; $i -lt $Steps.Count; $i++) {
        $last = ($i -eq $Steps.Count - 1)
        $dest = if ($last) { $FinalDest } else { '%TEMP%\catstep{0}' -f $i }
        $lines += ('  expand -F:{0} {1} "{2}"' -f $Steps[$i], $src, $dest)
        if (-not $last) { $src = '"{0}\{1}"' -f $dest, $Steps[$i] }
    }
    return $lines
}

# =========================================================================
# build the digests to look for
$needles = @()
if ($PSCmdlet.ParameterSetName -eq 'File') {
    if (-not (Test-Path $File)) { throw "File not found: $File" }
    $TargetName = [IO.Path]::GetFileName($File)
    foreach ($algo in 'SHA256', 'SHA1') {
        $h = Get-CatalogHash -Path $File -Algorithm $algo
        if ($h) {
            $needles += , $h
            Write-Host ("{0} catalog hash: {1}" -f $algo, ([BitConverter]::ToString($h) -replace '-', '')) -ForegroundColor Cyan
        }
    }
} else {
    $TargetName = $null
    $needles += , (Convert-HexToBytes $Hash)
    Write-Host ("Looking for: {0}" -f ([BitConverter]::ToString($needles[0]) -replace '-', '')) -ForegroundColor Cyan
}
if (-not $needles) { throw "Could not obtain any hash to search for." }

# extract
if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("catscan_" + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$origin = @{}
$inner  = @{}

$mode = if ($FullExtract) { 'full extraction' } else { 'catalogs-only' }
Write-Host "`n== Extracting ($mode) ==" -ForegroundColor Cyan
Write-Host "Working folder: $WorkDir"
if ($FullExtract) { Write-Host "Expanding every file; this can take a minute or two.`n" }
else { Write-Host "Pulling only cabs and catalogs; payload stays compressed.`n" }

$swE = [Diagnostics.Stopwatch]::StartNew()
$pkgCount = Expand-Package -Source $Package -Root $WorkDir -Full:$FullExtract -Origin $origin -Inner $inner
$swE.Stop()
Write-Host ("Extraction done: {0} package(s) in {1:n1}s.`n" -f $pkgCount, $swE.Elapsed.TotalSeconds) -ForegroundColor DarkGray

# search
$cats = @(Get-ChildItem -Path $WorkDir -Recurse -File -Include *.cat -ErrorAction SilentlyContinue)
Write-Host "== Searching ==" -ForegroundColor Cyan
$swS = [Diagnostics.Stopwatch]::StartNew()
$matched = @(Search-Catalogs -Cats $cats -Needles $needles -SearchThreads $SearchThreads)
$swS.Stop()
Write-Host ("`nSearch done in {0:n1}s.`n" -f $swS.Elapsed.TotalSeconds) -ForegroundColor DarkGray

# report
$origLabel = (Resolve-Path $Package).Path
if ($matched.Count) {
    Write-Host "MATCH -- catalog(s) containing the target hash:" -ForegroundColor Green

    # deliver the matching catalog(s) somewhere stable so they survive cleanup (both modes)
    $delivered = @{}
    if ($OutDir) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        foreach ($cat in $matched) {
            $leaf = [IO.Path]::GetFileName($cat)
            $dest = Join-Path $OutDir $leaf
            $k = 1
            while (Test-Path $dest) {   # avoid clobbering same-named catalogs
                $dest = Join-Path $OutDir ('{0}_{1}{2}' -f [IO.Path]::GetFileNameWithoutExtension($leaf), $k, [IO.Path]::GetExtension($leaf))
                $k++
            }
            Copy-Item -LiteralPath $cat -Destination $dest -Force
            $delivered[$cat] = (Resolve-Path $dest).Path
        }
    }

    foreach ($cat in $matched) {
        $catChain = @(Get-ExtractChain -FilePath $cat -Origin $origin -Inner $inner)   # [..cabs.., catLeaf]
        $catPathInPkg = ($origLabel + ' » ' + ($catChain -join ' » '))

        Write-Host ""
        Write-Host ("  catalog in package : {0}" -f $catPathInPkg)
        if ($delivered[$cat]) {
            Write-Host ("  catalog extracted  : {0}" -f $delivered[$cat]) -ForegroundColor Green
        }
        Write-Host    "  re-extract catalog :" -ForegroundColor DarkCyan
        Format-Recipe -Steps $catChain -Original $origLabel -FinalDest '.' | ForEach-Object { Write-Host $_ }

        # The catalog's container is NOT necessarily where the payload lives (component LCUs
        # keep catalogs in their own cab). Locate the actual payload among extracted files.
        $payHit = $null
        if ($TargetName) {
            $payHit = @($origin.Keys | Where-Object { [IO.Path]::GetFileName($_) -ieq $TargetName }) |
                      Select-Object -First 1
        }

        Write-Host    "  payload in package :" -ForegroundColor DarkCyan
        if ($payHit) {
            $payChain = @(Get-ExtractChain -FilePath $payHit -Origin $origin -Inner $inner)
            Write-Host ("                       {0} » {1}" -f $origLabel, ($payChain -join ' » '))
            Write-Host    "  re-extract payload :" -ForegroundColor DarkCyan
            Format-Recipe -Steps $payChain -Original $origLabel -FinalDest '.' | ForEach-Object { Write-Host $_ }
        } elseif (-not $FullExtract) {
            $what = if ($TargetName) { $TargetName } else { 'the payload' }
            Write-Host ("                       {0} was not unpacked in the catalogs-only pass." -f $what)
            Write-Host    "                       Re-run with -FullExtract to locate it inside the package." -ForegroundColor Yellow
        } else {
            Write-Host    "                       not present as a standalone file in this package." -ForegroundColor Yellow
            Write-Host    "                       Express/PSF cumulative updates ship the binary as a forward/reverse"
            Write-Host    "                       differential, not a whole file -- it's reconstructed at install time,"
            Write-Host    "                       so it can't be expanded directly from the .msu."
        }
    }
    if ($OutDir -and $delivered.Count) {
        Write-Host ""
        Write-Host ("Matching catalog(s) copied to: {0}" -f (Resolve-Path $OutDir).Path) -ForegroundColor Green
    }
    Write-Host ""
} else {
    Write-Host "No catalog in this package contains that hash." -ForegroundColor Yellow
    if (-not $FullExtract) {
        Write-Host "Catalogs-only pass found nothing. Some catalogs are only produced in CatRoot when" -ForegroundColor Yellow
        Write-Host "the update is applied; re-run with -FullExtract, or use the CatRoot before/after diff" -ForegroundColor Yellow
        Write-Host "on a serviced image." -ForegroundColor Yellow
    } else {
        Write-Host "Even full extraction found no matching catalog. Use the CatRoot before/after diff on a" -ForegroundColor Yellow
        Write-Host "serviced image -- the signing catalog is likely generated at install time." -ForegroundColor Yellow
    }
}

# cleanup: the temp work-dir is only kept when -KeepFiles is set. The catalog itself has
# already been copied to -OutDir, and all retrieval instructions reference the original
# package, so nothing above depends on the work-dir surviving.
if ($KeepFiles) {
    Write-Host ("Extracted work folder kept at: {0}" -f $WorkDir) -ForegroundColor DarkGray
} else {
    Remove-Item -Recurse -Force -Path $WorkDir -ErrorAction SilentlyContinue
}
