<#
.SYNOPSIS
Install okagent for the current user, or remove it again.

.DESCRIPTION
Copies okagent.exe and its PowerShell completion script to
%LOCALAPPDATA%\Programs\okagent, adds that directory to the user PATH and
sets SSH_AUTH_SOCK for the user to okagent's pipe, \\.\pipe\okagent-USER, so
every new shell finds the agent. No administrator rights are needed.

With -Autostart it also adds a shortcut to the Startup folder that runs
`okagent serve --daemon` at logon, and starts the agent now.

Run it again to upgrade. A running okagent from the install directory is
stopped first, since Windows cannot replace a running program, and started
again if it autostarts.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Autostart

.EXAMPLE
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\okagent\install.ps1" -Uninstall
#>
param(
    # Where okagent.exe goes.
    [string] $Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\okagent'),
    # Start the agent at logon, and now.
    [switch] $Autostart,
    # Leave the user's SSH_AUTH_SOCK alone.
    [switch] $NoAuthSock,
    # Remove what an install added.
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $Prefix 'okagent.exe'
$pipe = "\\.\pipe\okagent-$([Environment]::UserName)"
$shortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'okagent.lnk'

# The user PATH is read and written raw, so entries such as
# %USERPROFILE%\bin stay unexpanded.
function Get-UserPath {
    $key = Get-Item 'HKCU:\Environment'
    [string] $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
}

function Set-UserPath([string] $value) {
    Set-ItemProperty 'HKCU:\Environment' -Name Path -Value $value -Type ExpandString
}

function Test-SameDir([string] $a, [string] $b) {
    [Environment]::ExpandEnvironmentVariables($a).TrimEnd('\') -eq $b.TrimEnd('\')
}

# Tell Explorer, and so programs started from it later, that the user's
# environment changed.
function Send-EnvironmentChange {
    if (-not ('OkagentInstall.Native' -as [type])) {
        Add-Type -Namespace OkagentInstall -Name Native -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
    string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG
    [OkagentInstall.Native]::SendMessageTimeout([IntPtr] 0xffff, 0x1a, [UIntPtr]::Zero,
        'Environment', 2, 5000, [ref] $result) | Out-Null
}

function Stop-InstalledAgent {
    Get-Process okagent -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and (Test-SameDir $_.Path $exe) } |
        ForEach-Object {
            Write-Host "stopping okagent (pid $($_.Id))"
            Stop-Process -Id $_.Id -Force
            $_.WaitForExit(5000) | Out-Null
        }
}

if ($Uninstall) {
    Stop-InstalledAgent
    if (Test-Path $shortcut) { Remove-Item $shortcut }

    $entries = (Get-UserPath) -split ';' | Where-Object { $_ -and -not (Test-SameDir $_ $Prefix) }
    Set-UserPath ($entries -join ';')
    if ([Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK', 'User') -eq $pipe) {
        [Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', $null, 'User')
    }
    Send-EnvironmentChange

    # This script may be running from $Prefix; Windows lets it be deleted.
    if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
    Write-Host "removed okagent from $Prefix"
    Write-Host "Its config, %APPDATA%\okagent, is left in place."
    exit 0
}

$source = $PSScriptRoot
if (-not (Test-Path (Join-Path $source 'okagent.exe'))) {
    throw "okagent.exe is not next to this script in $source"
}

# An upgrade of an -Autostart install keeps it, and restarts the agent.
if (Test-Path $shortcut) { $Autostart = $true }

Stop-InstalledAgent
New-Item -ItemType Directory -Force $Prefix | Out-Null
if (-not (Test-SameDir $source $Prefix)) {
    foreach ($file in 'okagent.exe', 'okagent-completion.ps1', 'install.ps1', 'README.md', 'LICENSE') {
        $from = Join-Path $source $file
        if (Test-Path $from) { Copy-Item $from $Prefix -Force }
    }
}
# Files from a downloaded zip carry the internet zone mark; drop it, as
# installing is the decision to trust them.
Get-ChildItem $Prefix -File | Unblock-File

$userPath = Get-UserPath
if (-not ($userPath -split ';' | Where-Object { $_ -and (Test-SameDir $_ $Prefix) })) {
    Set-UserPath ((@($userPath.TrimEnd(';')) + $Prefix | Where-Object { $_ }) -join ';')
    Write-Host "added $Prefix to your PATH"
}
if (-not (($env:Path -split ';') | Where-Object { $_ -and (Test-SameDir $_ $Prefix) })) {
    $env:Path = "$env:Path;$Prefix"
}

if (-not $NoAuthSock) {
    $current = [Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK', 'User')
    if ($current -and $current -ne $pipe) {
        Write-Host "SSH_AUTH_SOCK was $current; okagent's pipe replaces it"
    }
    [Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', $pipe, 'User')
    $env:SSH_AUTH_SOCK = $pipe
}
Send-EnvironmentChange

if ($Autostart) {
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = $exe
    $link.Arguments = 'serve --daemon'
    $link.WorkingDirectory = $Prefix
    $link.Description = 'okagent: SSH agent backed by an OnlyKey'
    # Minimized: --daemon prints its PowerShell snippet and exits at once.
    $link.WindowStyle = 7
    $link.Save()
    Write-Host "added $shortcut"
    # Not -Wait, which also waits for the background agent it starts.
    (Start-Process -FilePath $exe -ArgumentList 'serve', '--daemon' -WindowStyle Hidden -PassThru).WaitForExit()
}

$version = & $exe --version
Write-Host "installed $version to $exe"
Write-Host ''
Write-Host 'Open a new terminal so it sees the new PATH and SSH_AUTH_SOCK.'
if (-not $Autostart) {
    Write-Host 'Start the agent with:  okagent serve --daemon | Invoke-Expression'
}
Write-Host 'For tab completion, add this line to your $PROFILE:'
Write-Host "  . '$(Join-Path $Prefix 'okagent-completion.ps1')'"
