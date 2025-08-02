# powershell-functions-007

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.16699957.svg)](https://doi.org/10.5281/zenodo.16699957)

PowerShell Functions 007  
Author: Peter Cullen Burbery  
PowerShell version: 7.0+ (Core only)  
Repository: [GitHub](https://github.com/PeterCullenBurbery/powershell-functions-007)  
PowerShell Gallery: [PowershellFunctions007](https://www.powershellgallery.com/packages/PowershellFunctions007)
## Overview

This module provides a collection of utilities for advanced PowerShell scripting on Windows, including environment configuration, system path management, time/date handling, Windows Explorer behavior tweaks, and more.

The module requires PowerShell 7+ (Core edition) and will throw an exception if imported into older or incompatible environments.

## Installation

### From PowerShell Gallery

```powershell
Install-Module -Name PowershellFunctions007
```

### From Local Clone

```powershell
# If you've cloned the repository manually
Import-Module ./PowershellFunctions007/PowershellFunctions007.psd1
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
- **`Get-PrimaryIPv4Address`** – Returns the most appropriate non-virtual, connected IPv4 address based on interface preference (e.g., Wi-Fi, Ethernet, Tailscale).

### File & Directory Utilities
- **`Get-FileSize`** – Calculates the total size (in bytes) of a file or all files within a directory.
- **`Get-FileSizeHumanReadable`** – Same as `Get-FileSize` but returns size in a readable string (e.g., "12.345 MB").

## 📁 Directory Structure

The `PowershellFunctions007/` folder contains the `.psd1` manifest and `.psm1` module.

## 📄 License

This module is shared under the [MIT License](https://opensource.org/licenses/MIT).

## ⚠️ Disclaimer

This is a development and educational project. All code is provided in good faith and intended for system automation, productivity, and learning purposes.

If you're a rights holder and want attribution changed or material removed, please contact the maintainer.

---

Maintained with care by Peter Cullen Burbery.

## 📘 Citation

If you use this module in your work, please cite the following:

> Peter Cullen Burbery. (2025). PowerShell Functions 007 (v2.4.0) [Software]. Zenodo. https://doi.org/10.5281/zenodo.16699957

I plan to configure Powershell actions to publish in the future to make publishing easier.