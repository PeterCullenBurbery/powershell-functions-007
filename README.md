# powershell-functions-007

PowerShell Functions 007  
Author: Peter Cullen Burbery  
PowerShell version: 7.0+ (Core only)  
Repository: [GitHub](https://github.com/PeterCullenBurbery/powershell-functions-007)

## Overview

This module provides a collection of utilities for advanced PowerShell scripting on Windows, including environment configuration, system path management, time/date handling, Windows Explorer behavior tweaks, and more.

The module requires PowerShell 7+ (Core edition) and will throw an exception if imported into older or incompatible environments.

## Install

```powershell
# From local development
Import-Module ./PowershellFunctions007.psd1
```

## Functions

### Time & Date Utilities
- **`Get-IanaTimeZone`** – Maps the current Windows time zone to the IANA time zone name.
- **`Get-IsoWeekDate`** – Returns ISO week format: `YYYY-Www-DDD`.
- **`Get-IsoOrdinalDate`** – Returns ordinal date format: `YYYY-DDD`.

### File Explorer Utilities
- **`Restart-FileExplorer`** – Restarts the Windows Explorer process.
- **`Bring-BackTheRightClickMenu`** – Enables Windows 10-style context menu in Windows 11.
- **`Use-Windows11RightClickMenu`** – Restores the default Windows 11 right-click context menu.

### Environment & PATH Management
- **`Add-ToPath`** – Adds a normalized path to the system `PATH` with deduplication.
- **`Remove-FromPath`** – Removes a path from the system `PATH` with normalization.
- **`Clean-Path`** – Cleans the system `PATH` by deduplicating and expanding all variables.
- **`Get-PowershellPath`** – Displays the current PATH as an indexed, formatted list.

### Security & Configuration
- **`Add-DefenderExclusion`** – Excludes a folder (or the parent folder of a file) from Microsoft Defender.
- **`Enable-LongFilePaths`** – Enables support for file paths longer than 260 characters via registry tweak.

### System Information
- **`Get-PowerShellVersionDetails`** – Detects feature availability in the current PowerShell session (e.g., ternary operators, parallelism).

### File & Directory Utilities
- **`Get-FileSize`** – Calculates the total size (in bytes) of a file or all files within a directory.
- **`Get-FileSizeHumanReadable`** – Same as `Get-FileSize` but returns size in a readable string (e.g., "12.345 MB").

## License

This module is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Release Notes

See `PowershellFunctions007.psd1` for full changelog.

---