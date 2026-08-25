# Security Catalogs Toolkit

**Manage Windows security catalogs (`.cat`) for standalone files pulled out of Windows Update packages.**

Some Windows binaries carry no embedded Authenticode signature; they are trusted because a [**security catalog**](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files) installed on the machine contains their hash and is itself signed by Microsoft or another trusted entity. This is common with files offered via Windows Update.

When troubleshooting or working around weird behaviors introduced by a changed binary, if you take a serviced file from one machine and drop it onto another, the file will read as *unsigned* on the target unless the matching catalog has been installed in that machine's catalog store. This is not always possible as the drop-in may be part of an update package that either predates the updates available on the target (making Windows skip the install altogether) or that includes other changes that shouldn't be applied to production machines.

In edge cases like these, you may want to manually add the required security catalog to make sure files have not been tampered with and pass audits.

***This toolkit covers that end‑to‑end problem!***

1. **Find and extract** the exact `.cat` that signs a given file, out of a Windows Update package (`.msu` / `.cab`).
2. **Inspect** a `.cat` to confirm it really covers your file.
3. **Install / list / remove** catalogs in the target machine's system catalog store (with a clean rollback path).

It does **not** create, re‑sign, or forge catalogs. Every catalog it handles is Microsoft's own, taken unchanged from an official update — the same catalog Windows Update would install itself.

---

## Contents

| Script | Purpose |
|---|---|
| `Find-CatalogForFile.ps1` | Given a file (or a catalog hash) and an update package, find and copy out the `.cat` that signs it. |
| `Inspect-Catalog.ps1` | Dump the contents of a `.cat`: catalog‑level attributes, members, and per‑member hashes/attributes. |
| `CatalogTool.ps1` | List, add, or remove catalogs in the machine's system catalog store. |

Every script supports `-Help` (e.g. `.\CatalogTool.ps1 -Help`) for detailed, per‑parameter help.

---

## Requirements

- Windows 10 / 11.
- Windows PowerShell 5.1 **or** PowerShell 7+. The parallel search (`-SearchThreads`) needs PowerShell 7+; it falls back to serial on 5.1.
- `expand.exe` and `wintrust.dll` — both ship with Windows; nothing to install.
- **Administrator** is required only for `CatalogTool.ps1 Add` / `Remove` (they modify the system store). Everything else runs as a normal user.
- Test on a VM or snapshot before touching a production machine.

---

## Typical workflow

You have a standalone file (say `fsquirt.exe`, responsible for Bluetooth send and receive interactions) and the Windows Update package it came from, and you want that file to verify as signed on a target machine.

**1. Find the catalog that signs the file and copy it out**

```powershell
.\Find-CatalogForFile.ps1 -Package .\windows10.0-kbXXXXXXX-x64.msu -File .\fsquirt.exe -SearchThreads 8
```

The matching `.cat` is copied to `.\matched-catalogs\`. The script also prints where the catalog (and, if present, the payload) sit inside the package, with a copy‑paste `expand` recipe to re‑extract them later straight from the original `.msu`.

**2. (Optional) Confirm the catalog covers your file**

```powershell
.\Inspect-Catalog.ps1 -Path .\matched-catalogs\<name>.cat -Attributes
```

Compare a member hash against your file's catalog hash:

```powershell
(Get-AppLockerFileInformation -Path .\fsquirt.exe).Hash   # Authenticode hash, as stored in catalogs
```

**3. On the target machine, install the catalog (elevated)**

```powershell
.\CatalogTool.ps1 List                                    # see what's already installed (no admin needed)
.\CatalogTool.ps1 Add -Catalog .\<name>.cat               # register it (Administrator required)
Get-AuthenticodeSignature C:\Windows\System32\fsquirt.exe # should now show Valid / Catalog
```

**4. Rollback, if needed (elevated)**

```powershell
.\CatalogTool.ps1 Remove -Catalog <name>.cat              # remove by the stored name shown in List
```

---

## Script reference

### Find-CatalogForFile.ps1

Computes the file's **catalog (Authenticode) hash** with `CryptCATAdminCalcHashFromFileHandle2` — the same hash Windows uses to look a file up in the catalog store, *not* the flat `Get-FileHash` value — then expands the package (following nested cabs) and byte‑searches every `.cat` for that hash. On a match it copies the catalog to `-OutDir` and reports the catalog's (and the payload's) location as a path within the original package.

Key parameters:

- `-Package <path>` — the `.msu` or `.cab` to search (required).
- `-File <path>` — the file whose signing catalog you want; the script computes the right hash. *(File mode)*
- `-Hash <hex>` — a catalog/Authenticode hash you already have, instead of a file. *(Hash mode)*
- `-FullExtract` — expand every file, not just cabs + catalogs. Slower; only needed when a catalogs‑only pass finds nothing or you want the payload on disk.
- `-SearchThreads <n>` — search catalogs across `n` threads (PowerShell 7+). Default 1.
- `-OutDir <path>` — where matched catalogs are copied. Default `.\matched-catalogs`. Use `-OutDir ''` to skip copying.
- `-KeepFiles` — keep the temp extraction folder (deleted otherwise).
- `-Help`.

Default behaviour is a fast **catalogs‑only** pass: it pulls only cabs and `.cat` files and leaves the (large) payload compressed. Recursion is protected against self‑referential / duplicate cabs by content (name + size, confirmed by hash on collision) and a depth cap.

### Inspect-Catalog.ps1

Read‑only. Opens a `.cat` with the `CryptCAT*` enumeration APIs and lists the catalog‑level attributes (e.g. `PackageName`, `OSAttr`) and every member with its reference tag/hash and filename.

- `-Path <path>` — the `.cat` to inspect (required).
- `-Attributes` — also dump every per‑member attribute (`File`, `OSAttr`, …).
- `-Help`.

Pair with `Get-AuthenticodeSignature .\file.cat` to see who signed the catalog and when.

### CatalogTool.ps1

Manages the system catalog store via the `CryptCATAdmin*` APIs — the same mechanism Windows Update uses, so an `Add` updates both the file store (`CatRoot`) and the catalog database (`catroot2`) and catalog‑signed files start verifying immediately.

- `-Action List` — list installed catalogs. **No admin needed.**
- `-Action Add -Catalog <path> [-Name <stored-name>]` — register a catalog. **Administrator required.**
- `-Action Remove -Catalog <stored-name>` — remove a catalog by the name shown in `List`. **Administrator required.**
- `-Help`.

`Add` / `Remove` check for elevation up front and stop with a clear message (rather than a cryptic Win32 error) if the session isn't elevated.

---

## Notes & caveats

- **Catalog hash ≠ flat hash.** For PE files (`.exe`, `.dll`, `.mui`) the catalog stores the *Authenticode* hash, not `Get-FileHash`. Use `-File` (which computes it correctly) or `Get-AppLockerFileInformation` when comparing by hand.
- **The catalog's container is not always where the payload lives.** Component cumulative updates keep catalogs in their own cab, separate from the binaries — so `Find-CatalogForFile.ps1` locates the payload independently and tells you honestly when it isn't present.
- **Express / PSF updates ship deltas, not whole files.** Modern cumulative updates often carry a binary as a forward/reverse differential that is reconstructed at install time, so the complete file frequently **cannot** be expanded from the `.msu` at all. Obtain the file itself from a serviced image (apply the update to an offline image with DISM and copy the file out); this toolkit's job is to get you the *catalog* for it.
- **Some catalogs only appear at install time.** If a package yields no matching catalog even with `-FullExtract`, the signing catalog is likely generated into `CatRoot` when the update is applied — capture it with a `CatRoot` before/after diff on a serviced image instead.
- **Always keep backups** of any system file you replace, and prefer testing on a snapshot. Adding a catalog is reversible with `CatalogTool.ps1 Remove`.

---

*These scripts call documented Win32 APIs and built‑in tools only. Validate them on a test machine before use.*
