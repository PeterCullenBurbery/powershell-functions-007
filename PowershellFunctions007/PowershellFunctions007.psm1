if ($PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw "This module is only supported in PowerShell 7 or higher (PSEdition 'Core')."
}

function Get-IanaTimeZone {
    $win_tz = (Get-TimeZone).Id
    $iana_tz = $null

    # Method 1: .NET TimeZoneInfo API (PowerShell 7.2+ / .NET 6+)
    if ([System.TimeZoneInfo].GetMethod("TryConvertWindowsIdToIanaId", [type[]]@([string],[string].MakeByRefType()))) {
        if ([System.TimeZoneInfo]::TryConvertWindowsIdToIanaId($win_tz, [ref] $iana_tz)) {
            return $iana_tz
        }
    }

    # Method 2: WinRT Calendar API (Windows 10+)
    try {
        return [Windows.Globalization.Calendar,Windows.Globalization,ContentType=WindowsRuntime]::new().GetTimeZone()
    } catch {}

    # Method 3: Parse TimeZoneMapping.xml
    $map_path = Join-Path $Env:WinDir 'Globalization\Time Zone\TimeZoneMapping.xml'
    if (Test-Path $map_path) {
        $map_xml = [xml](Get-Content $map_path)
        $node = $map_xml.TimeZoneMapping.MapTZ | Where-Object { $_.WinID -eq $win_tz -and $_.Default -eq "true" }
        if ($node) {
            return $node.TZID
        }
    }

    # Fallback to Windows ID
    return $win_tz
}

function Get-IsoWeekDate {
    param (
        [datetime]$date = (Get-Date)
    )

    if ([System.Type]::GetType("System.Globalization.ISOWeek")) {
        $iso_week = [System.Globalization.ISOWeek]::GetWeekOfYear($date)
        $iso_year = [System.Globalization.ISOWeek]::GetYear($date)
    } else {
        $iso_day = (([int]$date.DayOfWeek + 6) % 7) + 1
        $weekThursday = $date.AddDays(4 - $iso_day)
        $iso_year = $weekThursday.Year
        $iso_week = [System.Globalization.CultureInfo]::InvariantCulture.Calendar.GetWeekOfYear(
            $weekThursday,
            [System.Globalization.CalendarWeekRule]::FirstFourDayWeek,
            [System.DayOfWeek]::Monday
        )
    }

    $iso_day = (([int]$date.DayOfWeek + 6) % 7) + 1
    return "{0:0000}-W{1:000}-{2:000}" -f $iso_year, $iso_week, $iso_day
}

function Get-IsoOrdinalDate {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [DateTime] $Date = (Get-Date)
    )

    process {
        # Format as YYYY-DDD (year and 3-digit day-of-year)
        $ordinal = "{0:yyyy}-{1:D3}" -f $Date, $Date.DayOfYear
        Write-Output $ordinal
    }
}

function Restart-FileExplorer {
    <#
    .SYNOPSIS
    Restarts Windows File Explorer.

    .DESCRIPTION
    Stops the 'explorer' process and starts it again. This will close and reopen the desktop, taskbar, and any open File Explorer windows.

    .EXAMPLE
    Restart-FileExplorer

    Restarts the File Explorer process.
    #>

    [CmdletBinding()]
    param ()

    try {
        Write-Host "🔄 Stopping Explorer..." -ForegroundColor Yellow
        Stop-Process -Name explorer -Force -ErrorAction Stop
        Start-Sleep -Seconds 1

        Write-Host "🚀 Starting Explorer..." -ForegroundColor Green
        Start-Process explorer.exe
        Write-Host "✅ Explorer restarted successfully." -ForegroundColor Cyan
    }
    catch {
        Write-Host "❌ Failed to restart Explorer: $_" -ForegroundColor Red
    }
}

function Get-PowerShellVersionDetails {
    [OutputType([pscustomobject])]
    param ()

    $results = [ordered]@{}

    $results['PSVersion']         = $PSVersionTable.PSVersion.ToString()
    $results['PSEdition']         = $PSVersionTable.PSEdition
    $results['MajorVersion']      = $PSVersionTable.PSVersion.Major
    $results['ParallelSupported'] = $false
    $results['TernarySupported']  = $false
    $results['NullCoalescing']    = $false
    $results['PipelineChain']     = $false
    $results['PSStyleAvailable']  = $false
    $results['GetErrorAvailable'] = $false

    # 1. ForEach-Object -Parallel (robust test with -join)
    try {
        $output = 1..2 | ForEach-Object -Parallel { $_ * 2 }
        if (($output -join ',') -eq '2,4') {
            $results['ParallelSupported'] = $true
        }
    } catch {}

    # 2. Ternary operator
    try {
        $ternaryTest = Invoke-Expression '[bool]$x = $true; $x ? "yes" : "no"'
        if ($ternaryTest -eq 'yes') {
            $results['TernarySupported'] = $true
        }
    } catch {}

    # 3. Null-coalescing operator
    try {
        $nullCoalesce = Invoke-Expression '$null ?? "fallback"'
        if ($nullCoalesce -eq 'fallback') {
            $results['NullCoalescing'] = $true
        }
    } catch {}

    # 4. Pipeline chain operator (&&)
    try {
        $pipelineTest = Invoke-Expression '1..1 | ForEach-Object { "ok" } && "yes"'
        if ($pipelineTest -match 'yes') {
            $results['PipelineChain'] = $true
        }
    } catch {}

    # 5. $PSStyle
    try {
        if ($null -ne $PSStyle) {
            $results['PSStyleAvailable'] = $true
        }
    } catch {}

    # 6. Get-Error cmdlet
    try {
        if (Get-Command Get-Error -ErrorAction SilentlyContinue) {
            $results['GetErrorAvailable'] = $true
        }
    } catch {}

    # Final conclusion
    $results['Conclusion'] = if (
        $results['PSEdition'] -eq 'Core' -or
        $results['MajorVersion'] -ge 7 -or
        $results['ParallelSupported'] -or
        $results['TernarySupported'] -or
        $results['NullCoalescing'] -or
        $results['PipelineChain'] -or
        $results['PSStyleAvailable'] -or
        $results['GetErrorAvailable']
    ) {
        "✅ PowerShell 7+ (Core)"
    } elseif (
        $results['PSEdition'] -eq 'Desktop' -and
        $results['MajorVersion'] -eq 5
    ) {
        "🖥️ Windows PowerShell 5.1 (Desktop)"
    } else {
        "❓ Unknown or unsupported PowerShell version"
    }

    [pscustomobject]$results
}

function Add-ToPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToAdd
    )

    Write-Host "🔧 Input path: $PathToAdd"

    try {
        # Step 1: Resolve absolute path
        $absPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PathToAdd).Path)
        if (-not (Test-Path $absPath)) {
            throw "❌ Path does not exist: $absPath"
        }

        # If it's a file, get its parent folder
        if (-not (Get-Item $absPath).PSIsContainer) {
            $absPath = Split-Path $absPath
        }

        $normalized = $absPath.TrimEnd('\')
        Write-Host "📁 Normalized path: $normalized"

        # Step 2: Get PATH from registry (with symbolic variables)
        $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        )
        $rawPath = $reg.GetValue("Path", "", "DoNotExpandEnvironmentNames")
        $reg.Close()

        Write-Host "📍 Current PATH (raw):"
        Write-Host $rawPath
        
        # Step 3: Process and expand entries
        # Step 3: Normalize and deduplicate
        $entries = $rawPath -split ';'
        $normalizedLower = $normalized.ToLowerInvariant()
        $seen = @{ }
        $rebuilt = @($normalized)
        $seen[$normalizedLower] = $true
        $alreadyExists = $false

        Write-Host "🔍 Checking each existing PATH entry against target:"

        foreach ($entry in $entries) {
            $trimmed = $entry.Trim().TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).TrimEnd('\')
            $lowerExpanded = $expanded.ToLowerInvariant()

            # Log only if expansion changed the string
            if ($trimmed -ne $expanded) {
                Write-Host ("   - Original: {0,-70} → Expanded: {1}" -f $trimmed, $expanded)
            }

            # Detect if the normalized path already exists
            if ($lowerExpanded -eq $normalizedLower) {
                $alreadyExists = $true
            }

            # Avoid duplicates
            if (-not $seen.ContainsKey($lowerExpanded)) {
                $rebuilt += $expanded
                $seen[$lowerExpanded] = $true
            }
        }

        if ($alreadyExists) {
            Write-Host "✅ Path already present in system PATH (via expanded match)."
            return
        }

        $newPath = ($rebuilt -join ';')
        Write-Host "🧩 New PATH to set in registry (fully expanded):"
        Write-Host $newPath

        # Step 4: Overwrite registry with new flattened PATH
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path -Value $newPath
        Write-Host "✅ Path added to the top of system PATH."

        # Step 5: Broadcast environment change
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero

        $r = [Win32Functions.Win32SendMessageTimeout]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($r -eq [IntPtr]::Zero) {
            Write-Host "⚠️ Environment change broadcast may have failed."
        } else {
            Write-Host "📢 Environment update broadcast sent."
        }

        # Step 6: Check for refreshenv and invoke if available
        if (Get-Command -Name refreshenv -ErrorAction SilentlyContinue) {
            Write-Host "♻️  Calling 'refreshenv' to update current session..."
            refreshenv
        } else {
            Write-Host "ℹ️  'refreshenv' not available in this session."
        }

    } catch {
        Write-Error $_
    }
}

function Remove-FromPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToRemove
    )

    Write-Host "🧹 Input path to remove: $PathToRemove"

    try {
        # Step 1: Resolve absolute path
        $absPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PathToRemove).Path)
        if (-not (Test-Path $absPath)) {
            throw "❌ Path does not exist: $absPath"
        }

        if (-not (Get-Item $absPath).PSIsContainer) {
            $absPath = Split-Path $absPath
        }

        $normalized = $absPath.TrimEnd('\')
        $normalizedLower = $normalized.ToLowerInvariant()
        Write-Host "📁 Normalized path: $normalized"

        # Step 2: Read PATH from registry without expanding env vars
        $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        )
        $rawPath = $reg.GetValue("Path", "", "DoNotExpandEnvironmentNames")
        $reg.Close()

        Write-Host "📍 Current PATH (raw):"
        Write-Host $rawPath

        # Step 3: Split and rebuild entries (without the one we want to remove)
        $entries = $rawPath -split ';'
        $seen = @{}
        $rebuilt = @()
        $removed = $false

        Write-Host "🔍 Checking each PATH entry against target:"

        foreach ($entry in $entries) {
            $trimmed = $entry.Trim().TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).TrimEnd('\')
            $lowerExpanded = $expanded.ToLowerInvariant()

            # Log only if expansion changed the string
            if ($trimmed -ne $expanded) {
                Write-Host ("   - Original: {0,-70} → Expanded: {1}" -f $trimmed, $expanded)
            }

            if ($lowerExpanded -eq $normalizedLower) {
                Write-Host "❌ Match found. Skipping: $expanded"
                $removed = $true
                continue
            }

            if (-not $seen.ContainsKey($lowerExpanded)) {
                $rebuilt += $expanded
                $seen[$lowerExpanded] = $true
            }
        }

        if (-not $removed) {
            Write-Host "✅ Path not found in system PATH."
            return
        }

        $newPath = ($rebuilt -join ';')
        Write-Host "🧩 New PATH to set in registry (fully expanded):"
        Write-Host $newPath

        # Step 4: Update registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path -Value $newPath
        Write-Host "✅ Path removed from system PATH."

        # Step 5: Broadcast environment change
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero

        $r = [Win32Functions.Win32SendMessageTimeout]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($r -eq [IntPtr]::Zero) {
            Write-Host "⚠️ Environment change broadcast may have failed."
        } else {
            Write-Host "📢 Environment update broadcast sent."
        }

        # Step 6: Check for refreshenv and invoke if available
        if (Get-Command -Name refreshenv -ErrorAction SilentlyContinue) {
            Write-Host "♻️  Calling 'refreshenv' to update current session..."
            refreshenv
        } else {
            Write-Host "ℹ️  'refreshenv' not available in this session."
        }

    } catch {
        Write-Error $_
    }
}

function Get-FileSize {
    <#
    .SYNOPSIS
    Returns the total size in bytes of a file or all files within a directory.

    .DESCRIPTION
    This function accepts a path to either a file or directory.
    If a file, it returns its size.
    If a directory, it recursively computes the sum of all file sizes inside.

    .PARAMETER Path
    The path to the file or directory.

    .EXAMPLE
    Get-FileSize -Path "C:\Users\Administrator\Desktop"

    .OUTPUTS
    [Int64] The total size in bytes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path '$Path' does not exist."
    }

    $item = Get-Item -LiteralPath $Path

    if ($item.PSIsContainer) {
        $size = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
        return $size.Sum
    } else {
        return $item.Length
    }
}

function Get-FileSizeHumanReadable {
    <#
    .SYNOPSIS
    Returns the total size of a file or directory in a human-readable format with three decimal places.

    .DESCRIPTION
    This function takes a path to a file or directory. If it's a file, it reports its size.
    If it's a directory, it recursively sums all contained file sizes. The size is returned
    as a string formatted with the appropriate unit: bytes, KB, MB, GB, or TB.

    .PARAMETER Path
    The file or directory to evaluate.

    .EXAMPLE
    Get-FileSizeHumanReadable -Path "C:\Users\Administrator\Desktop"

    .OUTPUTS
    [string] A human-readable string like "123.456 MB".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path '$Path' does not exist."
    }

    $totalBytes = 0

    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $totalBytes = ((Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                       Measure-Object -Property Length -Sum).Sum) ?? 0
    } else {
        $totalBytes = $item.Length
    }

    switch ($true) {
        { $totalBytes -ge 1TB } { return '{0:N3} TB' -f ($totalBytes / 1TB) }
        { $totalBytes -ge 1GB } { return '{0:N3} GB' -f ($totalBytes / 1GB) }
        { $totalBytes -ge 1MB } { return '{0:N3} MB' -f ($totalBytes / 1MB) }
        { $totalBytes -ge 1KB } { return '{0:N3} KB' -f ($totalBytes / 1KB) }
        default                { return "$totalBytes bytes" }
    }
}

function Bring-BackTheRightClickMenu {
<#
.SYNOPSIS
Enables the classic Windows 10-style right-click context menu in Windows 11.

.DESCRIPTION
This function modifies the Windows registry to enable the classic context menu 
by creating a specific registry key under the current user's hive. It then 
restarts Windows File Explorer to apply the change.

The registry path created is:
  HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32

This tweak is commonly used on Windows 11 systems to restore the familiar 
context menu behavior found in Windows 10.

.EXAMPLE
Bring-BackTheRightClickMenu

Applies the registry tweak and restarts File Explorer.

.NOTES
Author: Peter Cullen Burbery
Requires: Windows 11, Administrator privileges may be needed in some configurations

.LINK
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry

#>
    [CmdletBinding()]
    param ()

    $registryPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

    try {
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }

        Set-ItemProperty -Path $registryPath -Name '(default)' -Value '' -Force
        Write-Host "✅ Classic right-click menu registry tweak applied."

        Write-Host "🔄 Restarting File Explorer..."
        Stop-Process -Name explorer -Force
        Start-Process explorer.exe

        Write-Host "✅ File Explorer restarted. Classic menu should be active."

    } catch {
        Write-Error "❌ Failed to apply classic menu tweak: $_"
    }
}

function Use-Windows11RightClickMenu {
<#
.SYNOPSIS
Restores the default Windows 11-style right-click context menu.

.DESCRIPTION
This function deletes the registry key that forces the classic Windows 10-style
context menu, restoring the default Windows 11 behavior.

It removes the following registry keys:
  HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}
  HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32

After cleaning up the registry, it restarts File Explorer so the change takes effect immediately.

.EXAMPLE
Use-Windows11RightClickMenu

Removes the registry tweak and restarts Explorer to restore the Windows 11 menu.

.NOTES
Author: Peter Cullen Burbery
Requires: Windows 11
Clears user-specific context menu override.

.LINK
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry

#>
    [CmdletBinding()]
    param ()

    $baseKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
    $subKey = "$baseKey\InprocServer32"

    try {
        if (Test-Path $subKey) {
            Remove-Item -Path $subKey -Recurse -Force
            Write-Host "🗑️ Removed subkey: $subKey"
        }

        if (Test-Path $baseKey) {
            Remove-Item -Path $baseKey -Recurse -Force
            Write-Host "🗑️ Removed key: $baseKey"
        }

        Write-Host "✅ Restored Windows 11 right-click menu."

        Write-Host "🔄 Restarting File Explorer..."
        Stop-Process -Name explorer -Force
        Start-Process explorer.exe

        Write-Host "✅ File Explorer restarted. Default menu should be active."

    } catch {
        Write-Error "❌ Failed to restore Windows 11 right-click menu: $_"
    }
}

function Add-DefenderExclusion {
    <#
    .SYNOPSIS
    Excludes a file or folder from Microsoft Defender.

    .DESCRIPTION
    If a file is provided, its parent folder will be excluded instead. Requires administrator privileges.

    .PARAMETER Path
    The absolute path to a file or folder to exclude from Defender.

    .EXAMPLE
    Add-DefenderExclusion -Path "C:\MyFolder"

    .EXAMPLE
    Add-DefenderExclusion -Path "C:\MyFolder\myfile.exe"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)

        if (-not (Test-Path $fullPath)) {
            throw "❌ Path does not exist: $fullPath"
        }

        $item = Get-Item $fullPath

        # If it's a file, use parent directory
        if (-not $item.PSIsContainer) {
            $fullPath = $item.Directory.FullName
        }

        # Normalize: convert to full path, replace forward slashes, ensure trailing backslash
        $normalizedPath = ([System.IO.Path]::GetFullPath($fullPath)) -replace '/', '\'
        if (-not $normalizedPath.EndsWith('\')) {
            $normalizedPath += '\'
        }

        # Add exclusion
        Add-MpPreference -ExclusionPath $normalizedPath

        Write-Host "✅ Excluded from Microsoft Defender: $normalizedPath"
    } catch {
        Write-Error "❌ Failed to exclude from Defender: $_"
    }
}

function Get-PowershellPath {
    <#
    .SYNOPSIS
    Displays the current user's PATH environment variable as a formatted table with index numbers.

    .DESCRIPTION
    Splits the PATH variable by semicolon, assigns each entry a zero-padded index, and displays it in a table.

    .EXAMPLE
    Get-PowershellPath
    #>

    $i = 1
    $env:Path -split ";" | ForEach-Object {
        [PSCustomObject]@{
            Index = "{0:000}" -f $i
            Path  = $_
        }
        $i++
    } | Format-Table -AutoSize
}

function Enable-LongFilePaths {
    <#
    .SYNOPSIS
    Enables long file path support in Windows (over 260 characters).

    .DESCRIPTION
    Modifies the registry to set LongPathsEnabled to 1. Requires admin privileges.

    .EXAMPLE
    Enable-LongFilePaths
    #>

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $valueName = "LongPathsEnabled"

    try {
        # Check if running as admin
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "❌ This script must be run as Administrator."
        }

        # Get current value
        $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop

        if ($current.$valueName -eq 1) {
            Write-Host "ℹ️ Long file paths are already enabled (LongPathsEnabled = 1)." -ForegroundColor Yellow
            return
        }

        # Set value to 1
        Set-ItemProperty -Path $regPath -Name $valueName -Value 1 -Type DWord
        Write-Host "✅ Long file paths have been enabled (LongPathsEnabled = 1)." -ForegroundColor Green
    }
    catch {
        Write-Error "❌ Failed to enable long file paths: $_"
    }
}

function Clean-Path {
    [CmdletBinding()]
    param ()

    try {
        # Step 1: Read PATH from registry (raw, with variables)
        $path_key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $raw_path = Get-ItemPropertyValue -Path $path_key -Name Path

        Write-Host "📍 Current PATH (raw):"
        Write-Host $raw_path

        # Step 2: Normalize, expand, deduplicate
        $entries = $raw_path -split ';'
        $seen = @{}
        $rebuilt = @()

        Write-Host "🔍 Normalizing entries:"
        foreach ($entry in $entries) {
            $trimmed = $entry.Trim().TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).TrimEnd('\')
            $lower = $expanded.ToLowerInvariant()

            if ($trimmed -ne $expanded) {
                Write-Host ("   - Original: {0,-70} → Expanded: {1}" -f $trimmed, $expanded)
            }

            if (-not $seen.ContainsKey($lower)) {
                $rebuilt += $expanded
                $seen[$lower] = $true
            }
        }

        $new_path = ($rebuilt -join ';')
        Write-Host "🧹 Cleaned PATH:"
        Write-Host $new_path

        # Step 3: Write back cleaned PATH to registry
        Set-ItemProperty -Path $path_key -Name Path -Value $new_path
        Write-Host "✅ Cleaned PATH written to registry."

        # Step 4: Broadcast environment change
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero

        $r = [Win32Functions.Win32SendMessageTimeout]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($r -eq [IntPtr]::Zero) {
            Write-Host "⚠️ Environment change broadcast may have failed."
        } else {
            Write-Host "📢 Environment update broadcast sent."
        }

        # Step 5: Refresh current session if possible
        if (Get-Command -Name refreshenv -ErrorAction SilentlyContinue) {
            Write-Host "♻️  Calling 'refreshenv' to update current session..."
            refreshenv
        } else {
            Write-Host "ℹ️  'refreshenv' not available in this session."
        }

    } catch {
        Write-Error $_
    }
}

function Get-PrimaryIPv4Address {
    <#
    .SYNOPSIS
        Returns the most appropriate non-virtual, connected IPv4 address.

    .DESCRIPTION
        Prefers interfaces like Wi-Fi, Ethernet, or Tailscale, and skips virtual/disconnected interfaces.

    .OUTPUTS
        [string] - IPv4 address or empty string if none found.
    #>
    try {
        $preferred_keywords = @("Wi-Fi", "Ethernet", "Tailscale")
        $excluded_keywords = @("VMware", "Virtual", "Bluetooth", "Loopback", "OpenVPN", "Disconnected")

        $interfaces = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike "169.254.*" -and
                $_.IPAddress -ne "127.0.0.1" -and
                $_.PrefixOrigin -ne "WellKnown" -and
                $_.ValidLifetime -gt 0
            } |
            Sort-Object -Property InterfaceMetric

        foreach ($preferred in $preferred_keywords) {
            $match = $interfaces | Where-Object {
                $_.InterfaceAlias -like "*$preferred*" -and
                ($excluded_keywords | Where-Object { $_ -in $_.InterfaceAlias }) -eq $null
            } | Select-Object -ExpandProperty IPAddress -First 1

            if ($match) { return $match }
        }

        # Fallback to the first non-excluded interface
        $match = $interfaces | Where-Object {
            ($excluded_keywords | Where-Object { $_ -in $_.InterfaceAlias }) -eq $null
        } | Select-Object -ExpandProperty IPAddress -First 1

        return $match
    } catch {
        return ""
    }
}

function Get-UnderscoreTimestamp {
<#
.SYNOPSIS
Generates an underscore-delimited, timezone-aware, nanosecond-precision timestamp string.

.DESCRIPTION
`Get-UnderscoreTimestamp` produces a precise timestamp string with the following components:
- Year (YYYY)
- Ordinal date (DDD) — repeated in the first and later sections
- Hour of day (HHH, zero-padded to 3 digits)
- Minute (MMM, zero-padded to 3 digits)
- Second (SSS, zero-padded to 3 digits)
- Nanoseconds (NNNNNNNNN, zero-padded to 9 digits)
- IANA timezone identifier (slashes replaced with `_slash_`)
- ISO year
- ISO week number (Wnnn)
- ISO day of week (001–007, Monday = 001)
- Calendar year (YYYY)
- Day of year (DDD)
- Unix epoch seconds
- Nanoseconds (again, zero-padded to 9 digits)

The output is suitable for precise, sortable, machine-readable timestamps with embedded timezone and ISO calendar context.

.PARAMETER Date
The date/time to format. Defaults to the current system date/time.

.EXAMPLE
PS> Get-UnderscoreTimestamp
2025_008_008_021_034_041_360527700_America_slash_New_York_2025_W032_005_2025_220_1754703281_360527700

.EXAMPLE
PS> Get-UnderscoreTimestamp -Date (Get-Date "2025-08-08T14:23:45.1234567Z")
2025_221_221_014_023_045_123456700_Coordinated_slash_Universal_2025_W032_005_2025_221_1754663025_123456700

.NOTES
- Relies on `Get-IanaTimeZone` for timezone conversion.
- Relies on `Get-IsoWeekDate` for ISO year/week/day calculations.
- Day-of-year (ordinal) is computed directly from `$Date.DayOfYear`.
- Nanoseconds are computed from .NET ticks (`Ticks % 10000000 * 100`).
#>
    [CmdletBinding()]
    param(
        [datetime]$Date = (Get-Date)
    )

    # Year and ordinal date (day of year, zero-padded to 3)
    $year = $Date.Year
    $ordinal = '{0:D3}' -f $Date.DayOfYear

    # Time components (zero-padded to 3)
    $hour   = '{0:000}' -f $Date.Hour
    $minute = '{0:000}' -f $Date.Minute
    $second = '{0:000}' -f $Date.Second

    # Nanoseconds from ticks (ticks are 100ns)
    $ticksWithinSecond = $Date.Ticks % 10000000
    $nanoseconds = '{0:000000000}' -f ($ticksWithinSecond * 100)

    # IANA timezone with _slash_ replacement
    $iana = Get-IanaTimeZone
    $tz_formatted = $iana -replace '/', '_slash_'

    # ISO year-week-weekday
    $iso = Get-IsoWeekDate -date $Date
    if ($iso -notmatch '^(?<y>\d{4})-W(?<w>\d{3})-(?<d>\d{3})$') {
        throw "Unexpected ISO week format: $iso"
    }
    $iso_year = $Matches['y']
    $iso_week = $Matches['w']
    $iso_dow  = $Matches['d']

    # Unix seconds
    $unixSeconds = [DateTimeOffset]$Date
    $unixSeconds = $unixSeconds.ToUnixTimeSeconds()

    # Assemble final string
    return "$year`_${ordinal}`_${ordinal}`_${hour}`_${minute}`_${second}`_${nanoseconds}`_${tz_formatted}`_${iso_year}_W${iso_week}_$iso_dow`_${year}_$ordinal`_${unixSeconds}_$nanoseconds"
}