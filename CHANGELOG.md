# Changelog

All notable changes to this project will be documented in this file.

## [2.3.0] - 2025-008-001 019.018.025.242875400 America/New_York 2025-W031-005 2025-213

### Added

- Added `Get-PrimaryIPv4Address`, a function that returns the best non-virtual, connected IPv4 address. It prioritizes interfaces like Wi-Fi, Ethernet, or Tailscale while skipping loopbacks and disconnected/virtual interfaces. Useful for cleanly logging or displaying the primary local IP.

## [2.2.0] - 2025-008-001 016.035.013.346602800 America/New_York 2025-W031-005 2025-213

- Added Zenodo information to including, but not limited to, CITATION.cff, and README.md.
- Icon URL/URI https://zenodo.org/badge/DOI/10.5281/zenodo.16699957.svg added.
- Help Info URI/URL 'https://github.com/PeterCullenBurbery/powershell-functions-007#readme' added.

## [2.1.0] - 2025-008-001 016.003.049.190649500 America/New_York 2025-W031-005 2025-213

- publishing for Zenodo.

## [2.0.0] - 2025-007-025@1.29 PM

- I moved PowershellFunctions007 from https://github.com/PeterCullenBurbery/powershell-modules to https://github.com/PeterCullenBurbery/powershell-functions-007. URL has been updated accordingly.

## [1.9.0] - 2025-007-024@2.17 PM

### Added

- Added Clean-Path function to normalize and deduplicate the system PATH. This function expands environment variables, removes blank entries, removes case-insensitive duplicates, and broadcasts the updated environment block. Clean-Path complements Add-ToPath and Remove-FromPath by ensuring overall cleanliness of the PATH variable.

## [1.8.2] - 2025-007-021@1.51 PM

- Updated GUID. GUID was the same as PowershellFunctions@https://www.powershellgallery.com/packages/PowershellFunctions/.

## [1.8.1] - 2025-007-021@12.12 PM

### Added

- Added runtime enforcement of PowerShell 7 (Core edition) to the module file. Now, if the module is imported in an unsupported host (e.g., Windows PowerShell 5.1), it throws a clear exception. This guarantees the module is only run where PowerShell 7+ features like ?? are supported.

## [1.8.0] - 2025-007-021@11.06 PM

- This release locks the module to Windows PowerShell 7 only. This version uses 7-syntax like ?? null-coalescing operator. Fixes an issue with 0 bytes files. Before, Get-FileSizeHumanReadable "C:\empty-folder" would return " bytes". Now Get-FileSizeHumanReadable "C:\empty-folder" returns "0 bytes".

## [1.7.3] - 2025-007-018@10.06 PM

- Removed C# components. StartProcessLongFilePath was not working so I removed it.

## [1.7.2] - 2025-007-018@3.35 PM

- Update release notes.

## [1.7.1] - 2025-007-018@3.30 PM

- Removed Start-ProcessLongFilePath from the module. The DLL-based cmdlet was deemed too complex.

## [1.7.0] - 2025-007-018@1.51 PM

### Added

- Added Start-ProcessLongFilePath, a wrapper for a C#-based cmdlet that launches processes using paths exceeding Windows MAX_PATH limitations. Useful for deeply nested folders or long file names. Includes support for optional arguments.

## [1.6.0] - 2025-007-017@5.19 PM

### Added

- Added Enable-LongFilePaths to programmatically enable support for file paths longer than 260 characters. The function checks the current registry value and only modifies it if necessary.

## [1.5.0] - 2025-007-015@4.22 PM

### Added

- Add-ToPath and Remove-FromPath now automatically call `refreshenv` if available, updating the current session immediately after modifying the system PATH.

## [1.4.0] - 2025-007-015@2.08 PM

### Added

- Added Get-PowershellPath to display the PATH environment variable in a zero-padded, indexed table. Uses Format-Table for clear formatting and supports inspection of system path entries.

## [1.3.0] - 2025-007-015@10.50 AM

### Added

- Added Add-DefenderExclusion to exclude folders from Microsoft Defender. Automatically excludes the parent folder if a file is specified. Requires administrator privileges.

## [1.2.0] - 2025-007-015@8.59 AM

- Fixed Add-ToPath and Remove-FromPath to correctly resolve relative paths (e.g., ".") using Resolve-Path. Improves reliability when modifying system PATH from any location.

## [1.1.0] - 2025-007-014@8.26 PM

### Added

- Added Bring-BackTheRightClickMenu and Use-Windows11RightClickMenu to toggle classic and default context menus in Windows 11. Improved tagging and documentation.


## [1.0.0] - 2025-007-014@4.16 PM

- Initial release: includes time zone resolution, ISO week and ordinal date formatting, File Explorer restart, and PowerShell version capability detection.