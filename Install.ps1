<#
.SYNOPSIS
    Helper script for installing/uninstalling Microsoft Defender for Downlevel Servers.
.DESCRIPTION
    On install scenario:
        It first removes MMA workspace when RemoveMMA guid is provided.
        Next uninstalls SCEP if present and OS version is Server2012R2
        Next installs two hotfixes required by the MSI (if they are not installed)
        Next installs the Microsoft Defender for Downlevel Servers MSI (i.e. md4ws.msi)
        Finally, it runs the onboarding script when OnboardingScript is provided.
    On uninstall scenario:
        It will run the offboarding script, if provided.
        Uninstalls the MSI.
        Removes Defender Powershell module, if loaded inside current Powershell session.
.INPUTS
    md4ws.msi
.OUTPUTS
    none
.EXAMPLE
    .\Install.ps1
.EXAMPLE
    .\Install.ps1 -UI -NoMSILog -NoEtl
.EXAMPLE
    .\Install.ps1 -Uninstall
.EXAMPLE
    .\Install.ps1 -Uninstall -NoEtl
#>
param(
    [Parameter(ParameterSetName = 'install')]
    ## MMA Workspace Id to be removed
    [guid] $RemoveMMA,
    [Parameter(ParameterSetName = 'install')]
    ## Path to onboarding script (required by WD-ATP)
    [string] $OnboardingScript,    
    [Parameter(ParameterSetName = 'install')]
    ## Installs devmode msi instead of the realeased one
    [switch] $DevMode,
    [Parameter(ParameterSetName = 'uninstall', Mandatory)]
    ## Uninstalls Microsoft Defender for Downlevel Servers. Offboarding has to be run manually prior to uninstall.
    [switch] $Uninstall,
    [Parameter(ParameterSetName = 'uninstall')]
    [Parameter(ParameterSetName = 'install')]
    ## Offboarding script to run prior to uninstalling/reinstalling MSI 
    [string] $OffboardingScript,
    [Parameter(ParameterSetName = 'install')]
    [Parameter(ParameterSetName = 'uninstall')]
    ## Enables UI in MSI 
    [switch] $UI,
    [Parameter(ParameterSetName = 'install')]
    ## Put WinDefend in passive mode.
    [switch] $Passive,
    [Parameter(ParameterSetName = 'install')]
    [Parameter(ParameterSetName = 'uninstall')]
    ## Disable MSI Logging
    [switch] $NoMSILog,
    [Parameter(ParameterSetName = 'install')]
    [Parameter(ParameterSetName = 'uninstall')]
    ## Disable ETL logging
    [switch] $NoEtl)
 
    
    
function Get-TraceMessage {
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Message,
        [Parameter(Position = 1)][uint16] $SkipFrames = 2,
        [datetime] $Date = (Get-Date))
    function Get-Time {
        param([datetime] $Date = (Get-Date))
        return $Date.ToString('yy/MM/ddTHH:mm:ss.fff')
    }
    
    [System.Management.Automation.CallStackFrame[]] $stackFrames = Get-PSCallStack
    for ($k = $SkipFrames; $k -lt $stackFrames.Count; $k++) {
        $currentPS = $stackFrames[$k]
        if ($null -ne $currentPS.ScriptName -or $currentPS.FunctionName -eq "<ScriptBlock>") {
            [int] $lineNumber = $currentPS.ScriptLineNumber
            if ($null -ne $currentPS.ScriptName) {
                $scriptFullName = $currentPS.ScriptName
            } else {
                if ($null -eq (Get-Variable VMPosition -ErrorAction:Ignore)) {
                    $scriptFullName = '<interactive>'
                } else {
                    $lineNumber += $VMPosition.Line
                    $scriptFullName = $VMPosition.File
                }
            }
            
            $scriptName = $scriptFullName.Substring(1 + $scriptFullName.LastIndexOf('\'))  
            return "[{0}:{1:00} {2} {3}:{4,-3}] {5}" -f $env:COMPUTERNAME, [System.Threading.Thread]::CurrentThread.ManagedThreadId, (Get-Time $date), $scriptName, $lineNumber, $message
        }
    }
    
    throw "Cannot figure out the right caller for $SkipFrames, $stackFrames"
}
    
function Exit-Install {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)] [string] $Message,
        [Parameter(Mandatory)] [uint32] $ExitCode)
    $fullMessage = Get-TraceMessage -Message:$Message
    Write-Error $fullMessage -ErrorAction:Continue
    exit $ExitCode
}
function Trace-Message {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)] [string] $Message,
        [Parameter(Position = 1)][uint16] $SkipFrames = 2,
        [datetime] $Date = (Get-Date))
    $fullMessage = Get-TraceMessage -Message:$Message -SkipFrames:$SkipFrames -Date:$Date
    Write-Host $fullMessage
}

function Trace-Warning {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string] $Message)
    $fullMessage = Get-TraceMessage "WARNING: $message"
    ## not using Write-Warning is intentional.
    Write-Host $fullMessage
}

function Use-Object {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()] [AllowEmptyCollection()] [AllowNull()]
        [Object]$InputObject,
        [Parameter(Mandatory = $true)]
        [scriptblock] $ScriptBlock,
        [Object[]]$ArgumentList
    )

    try {
        & $ScriptBlock @ArgumentList
    } catch {
        throw
    } finally {
        if ($null -ne $InputObject -and $InputObject -is [System.IDisposable]) {
            $InputObject.Dispose()
        }
    }
}

function New-TempFile {
    #New-TemporaryFile is not available on PowerShell 4.0.
    [CmdletBinding()]
    [OutputType('System.IO.FileInfo')]
    param()

    $path = [System.Io.Path]::GetTempPath() + [guid]::NewGuid().Guid + '.tmp'
    return New-Object -TypeName 'System.IO.FileInfo' -ArgumentList:$path
}

function Measure-Process {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -LiteralPath:$_ -PathType:Leaf })]
        [string] $FilePath,

        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,
        [switch] $PassThru,
        [ValidateScript( { Test-Path -LiteralPath:$_ -PathType:Container })]
        [string] $WorkingDirectory = (Get-Location).Path,
        [uint16] $SkipFrames = 3)

    Trace-Message "Running $FilePath $ArgumentList in $WorkingDirectory ..." -SkipFrames:$SkipFrames

    $startParams = @{
        FilePath               = $FilePath
        WorkingDirectory       = $WorkingDirectory
        Wait                   = $true
        NoNewWindow            = $true
        PassThru               = $true        
        RedirectStandardOutput = New-TempFile
        RedirectStandardError  = New-TempFile
    }
    if ($ArgumentList) {
        $startParams.ArgumentList = $ArgumentList
    }
    $info = @{ ExitCode = 1 }
    try {
        Use-Object ($proc = Start-Process @startParams) {
            param ($ArgumentList, $SkipFrames)
            [TimeSpan] $runningTime = ($proc.ExitTime - $proc.StartTime).Ticks
            $exitCode = $info.exitCode = $proc.ExitCode
            $info.ExitTime = $proc.ExitTime
            Get-Content -Path $startParams.RedirectStandardOutput | ForEach-Object {
                Trace-Message "[StandardOutput]: $_" -Date:$info.ExitTime -SkipFrames:$(1 + $SkipFrames)
            }
            Get-Content -Path $startParams.RedirectStandardError | ForEach-Object {
                Trace-Message "[StandardError]: $_" -Date:$info.ExitTime -SkipFrames:$(1 + $SkipFrames)
            }
            $commandLine = $(Split-Path -Path:$FilePath -Leaf)
            if ($ArgumentList) {
                $commandLine += " $ArgumentList"
            }
            $message = if (0 -eq $exitCode) {
                "Command `"$commandLine`" run for $runningTime"
            } else {
                "Command `"$commandLine`" failed with error $exitCode after $runningTime"
            }
            Trace-Message $message -SkipFrames:$SkipFrames           
            if (-not $PassThru -and 0 -ne $exitCode) {
                exit $exitCode
            }
        } -ArgumentList:$ArgumentList, (2 + $SkipFrames)
    } catch {
        throw
    } finally {
        Remove-Item -LiteralPath:$startParams.RedirectStandardError.FullName -Force -ErrorAction:SilentlyContinue
        Remove-Item -LiteralPath:$startParams.RedirectStandardOutput.FullName -Force -ErrorAction:SilentlyContinue
    }
    if ($PassThru) {
        return $info.ExitCode
    }
}

function Test-CurrentUserIsInRole {
    [CmdLetBinding()]
    param([string[]] $SIDArray)
    foreach ($sidString in $SIDArray) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
        $role = $sid.Translate([Security.Principal.NTAccount]).Value
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole($role)) {
            return $true
        }
    }
    return $false
}



function Get-GuidHelper {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] [string] $Pattern
    )
    ## guids are regenerated every time we change .wx{i,s} files
    ## @note: SilentlyContinue just in case $Path does not exist.
    $result = @(Get-ChildItem -LiteralPath:$LiteralPath -ErrorAction:SilentlyContinue |
        Where-Object { $_.GetValue($Name) -match $Value -and $_.PSChildName -match $Pattern } |
        Select-Object -ExpandProperty:PSChildName)
    if ($result.Count -eq 1) {
        return $result[0]
    }
    return $null
}

function Get-UninstallGuid {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)] [string] $DisplayName
    )
    $extraParams = @{
        Name        = 'DisplayName'
        Value       = $DisplayName
        LiteralPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        Pattern     = '^{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}}$'
    }
    
    return Get-GuidHelper @extraParams
}

function Get-CodeSQUID {
    [CmdletBinding()]
    param (
        [string] $ProductName
    )
    
    if (-not (Get-PSDrive -Name:'HKCR' -ErrorAction:SilentlyContinue)) {
        $null = New-PSDrive -Name:'HKCR' -PSProvider:Registry -Root:HKEY_CLASSES_ROOT -Scope:Script
        Trace-Message "'HKCR' PSDrive created(script scoped)"
    }
    ## msi!MsiGetProductInfoW
    $extraParams = @{
        Name        = 'ProductName'
        Value       = $ProductName
        LiteralPath = 'HKCR:\Installer\Products'
        Pattern     = '^[0-9a-f]{32}$'
    }
    
    return Get-GuidHelper @extraParams
}

function Test-IsAdministrator {
    Test-CurrentUserIsInRole 'S-1-5-32-544'
}

function Get-FileVersion {
    [OutputType([System.Version])]
    [CmdletBinding()]
    param([string] $File)
    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File)
    New-Object System.Version $($versionInfo.FileMajorPart), $($versionInfo.FileMinorPart), $($versionInfo.FileBuildPart), $($versionInfo.FilePrivatePart)
}

function Get-OSVersion {
    [OutputType([System.Version])]
    [CmdletBinding()]
    param ()
    # [environment]::OSVersion.Version on PowerShell ISE has issues on 2012R2 (see https://devblogs.microsoft.com/scripting/use-powershell-to-find-operating-system-version/)
    # Get-CIMInstance provides a string where we don't get the revision. 
    return Get-FileVersion -File:"$env:SystemRoot\system32\ntoskrnl.exe"
}

function Invoke-Member {
    [CmdletBinding()]
    param ( [Object] $ComObject,
        [Parameter(Mandatory)] [string] $Method,
        [System.Object[]] $ArgumentList)
    if ($ComObject) {
        return $ComObject.GetType().InvokeMember($Method, [System.Reflection.BindingFlags]::InvokeMethod, $null, $ComObject, $ArgumentList)
    }
}

function Invoke-GetProperty {
    [CmdletBinding()]
    param ( [Object] $ComObject,
        [Parameter(Mandatory)] [string] $Property,
        [Parameter(Mandatory)] [int] $Colummn)
    if ($ComObject) {
        return $ComObject.GetType().InvokeMember($Property, [System.Reflection.BindingFlags]::GetProperty, $null, $ComObject, $Colummn)
    }
}

function ReleaseComObject {
    [CmdletBinding()]
    param ([Object] $ComObject)
    if ($ComObject) {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject)
    }
}

function Get-MsiFilesInfo {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string] $MsiPath)

    function Get-MsiFileTableHelper {
        param ([Parameter(Mandatory)] [Object] $Database)
        try {
            ## @see https://docs.microsoft.com/en-us/windows/win32/msi/file-table
            $view = Invoke-Member $Database 'OpenView' ("SELECT * FROM File")
            Invoke-Member $view 'Execute'
            $rez = @{}
            while ($null -ne ($record = Invoke-Member $view 'Fetch')) {
                $file = Invoke-GetProperty $record 'StringData' 1
                $FileName = Invoke-GetProperty $record 'StringData' 3
                $versionString = $(Invoke-GetProperty $record 'StringData' 5)
                $version = if ($versionString) {
                    [version]$versionString
                } else {
                    $null
                }
                $rez.$file = [ordered] @{
                    Component  = Invoke-GetProperty $record 'StringData' 2
                    FileName   = $FileName
                    FileSize   = [convert]::ToInt64($(Invoke-GetProperty $record 'StringData' 4))
                    Version    = $version
                    Language   = Invoke-GetProperty $record 'StringData' 6
                    Attributes = [convert]::ToInt16($(Invoke-GetProperty $record 'StringData' 7))
                    Sequence   = [convert]::ToInt16($(Invoke-GetProperty $record 'StringData' 8))
                }
                ReleaseComObject $record
            }
            return $rez
        } catch {
            throw
        } finally {
            Invoke-Member $view 'Close'
            ReleaseComObject $view 
        }
    }
    
    try {
        $installer = New-Object -ComObject:WindowsInstaller.Installer        
        ## @see https://docs.microsoft.com/en-us/windows/win32/msi/database-object
        $database = Invoke-Member $installer 'OpenDatabase' ($MsiPath, 0)
        return Get-MsiFileTableHelper -Database:$database
    } catch {
        throw
    } finally {
        ReleaseComObject $database
        ReleaseComObject $installer
    }
}

function Test-ExternalScripts {
    [CmdletBinding()]
    param ()
    if ($OnboardingScript.Length) {
        if (-not (Test-Path -LiteralPath:$OnboardingScript -PathType:Leaf)) {
            Exit-Install -Message:"$OnboardingScript does not exist" -ExitCode:$ERR_ONBOARDING_NOT_FOUND
        }       
        ## validate it is an "onboarding" script.
        $on = Get-Content -LiteralPath:$OnboardingScript | Where-Object {
            $_ -match 'reg\s+add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+OnboardingInfo'
        }
        if ($on.Length -eq 0) {
            Exit-Install -Message:"Not an onboarding script: $OnboardingScript" -ExitCode:$ERR_INVALID_PARAMETER
        }

        if (-not (Test-IsAdministrator)) {
            Exit-Install -Message:'Onboarding scripts need to be invoked from an elevated process' -ExitCode:$ERR_INSUFFICIENT_PRIVILEGES
        }
    }

    if ($OffboardingScript.Length) {
        if (-not (Test-Path -LiteralPath:$OffboardingScript -PathType:Leaf)) {
            Exit-Install -Message:"$OffboardingScript does not exist" -ExitCode:$ERR_OFFBOARDING_NOT_FOUND
        }

        $off = Get-Content -LiteralPath:$OffboardingScript | Where-Object {
            $_ -match 'reg\s+add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A'
        }
        
        if ($off.Length -eq 0) {
            Exit-Install -Message:"Not an offboarding script: $OffboardingScript" -ExitCode:$ERR_INVALID_PARAMETER
        }

        if (-not (Test-IsAdministrator)) {
            Exit-Install -Message:'Offboarding scripts need to be invoked from an elevated process' -ExitCode:$ERR_INSUFFICIENT_PRIVILEGES
        }
    }   
}

function Get-RegistryKey {
    [CmdLetBinding()]
    param([Parameter(Mandatory)][string] $LiteralPath,
        [Parameter(Mandatory)][string] $Name)

    $k = Get-ItemProperty -LiteralPath:$LiteralPath -Name:$Name -ErrorAction SilentlyContinue
    if ($k) {
        return $k.$Name
    }

    return $null
}

function Invoke-MpCmdRun {
    [CmdLetBinding()]
    param(
        [AllowEmptyString()] [AllowEmptyCollection()] [string[]] $ArgumentList,
        [uint16] $SkipFrames = 4
    )
    $startParams = @{
        FilePath   = Join-Path -Path:$(Get-RegistryKey -LiteralPath:'HKLM:\SOFTWARE\Microsoft\Windows Defender' -Name:'InstallLocation') 'MpCmdRun.exe'
        SkipFrames = $SkipFrames
    }   
    if ($ArgumentList) {
        $startParams.ArgumentList = $ArgumentList
    }
    Measure-Process @startParams
}

@(
    @{ Name = 'ERR_INTERNAL'; Value = 1 }
    @{ Name = 'ERR_INSUFFICIENT_PRIVILEGES'; Value = 3 }
    @{ Name = 'ERR_NO_INTERNET_CONNECTIVITY'; Value = 4 }
    @{ Name = 'ERR_CONFLICTING_APPS'; Value = 5 }
    @{ Name = 'ERR_INVALID_PARAMETER'; Value = 6 }
    @{ Name = 'ERR_UNSUPPORTED_DISTRO'; Value = 10 }
    @{ Name = 'ERR_UNSUPPORTED_VERSION'; Value = 11 }
    @{ Name = 'ERR_PENDING_REBOOT'; Value = 12 }
    @{ Name = 'ERR_INSUFFICIENT_REQUIREMENTS'; Value = 13 }
    @{ Name = 'ERR_UNEXPECTED_STATE'; Value = 14 }
    @{ Name = 'ERR_CORRUPTED_FILE'; Value = 15 }
    @{ Name = 'ERR_MSI_NOT_FOUND'; Value = 16 }
    @{ Name = 'ERR_ALREADY_UNINSTALLED'; Value = 17 }
    @{ Name = 'ERR_DIRECTORY_NOT_WRITABLE'; Value = 18 }
    @{ Name = 'ERR_MDE_NOT_INSTALLED'; Value = 20 }
    @{ Name = 'ERR_INSTALLATION_FAILED'; Value = 21 }
    @{ Name = 'ERR_UNINSTALLATION_FAILED'; Value = 22 }
    @{ Name = 'ERR_FAILED_DEPENDENCY'; Value = 23 }
    @{ Name = 'ERR_ONBOARDING_NOT_FOUND'; Value = 30 }
    @{ Name = 'ERR_ONBOARDING_FAILED'; Value = 31 }
    @{ Name = 'ERR_OFFBOARDING_NOT_FOUND'; Value = 32 }
    @{ Name = 'ERR_OFFBOARDING_FAILED'; Value = 33 }
    @{ Name = 'ERR_NOT_ONBOARDED'; Value = 34 }
    @{ Name = 'ERR_NOT_OFFBOARDED'; Value = 35 }
    @{ Name = 'ERR_MSI_USED_BY_OTHER_PROCESS'; Value = 36 }
) | ForEach-Object { 
    Set-Variable -Name:$_.Name -Value:$_.Value -Option:Constant -Scope:Script 
}

Test-ExternalScripts
if ('Tls12' -notin [Net.ServicePointManager]::SecurityProtocol) {
    ## Server 2016/2012R2 might not have this one enabled and all Invoke-WebRequest might fail.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Trace-Message "[Net.ServicePointManager]::SecurityProtocol updated to '$([Net.ServicePointManager]::SecurityProtocol)'"
} 

$osVersion = Get-OSVersion

## make sure we capture logs by default.
[bool] $etl = -not $NoEtl.IsPresent
[bool] $log = -not $NoMSILog.IsPresent

[string] $msi = if ((-not $DevMode.IsPresent) -and (Test-Path -Path "$PSScriptRoot\md4ws.msi")) {
    Join-Path -Path:$PSScriptRoot "md4ws.msi"
} else {
    ## for devmode we always capture logs.
    $etl = $true
    $log = $true
    Join-Path -Path:$PSScriptRoot "md4ws-devmode.msi"
}

$action = if ($Uninstall.IsPresent) { 'uninstall' }  else { 'install' }
$logBase = "$action-$env:COMPUTERNAME-$osVersion"

## make sure $PSSCriptRoot is writable. 
$tempFile = Join-Path -Path:$PSScriptRoot "$([guid]::NewGuid().Guid).tmp"
Set-Content -LiteralPath:$tempFile -Value:'' -ErrorAction:SilentlyContinue
if (-not (Test-Path -LiteralPath:$tempFile -PathType:Leaf)) {
    Exit-Install "Cannot create $tempFile. Is $PSScriptRoot writable?" -ExitCode:$ERR_DIRECTORY_NOT_WRITABLE
} else {
    Remove-Item -LiteralPath:$tempFile -ErrorAction:SilentlyContinue
    $tempFile = $null
}

if ($etl) {
    $guid = [guid]::NewGuid().Guid
    $wdprov = Join-Path -Path:$env:TEMP "$guid.temp"
    $tempFile = Join-Path -Path:$env:TEMP "$guid.etl"
    $etlLog = "$PSScriptRoot\$logBase.etl"
    $wppTracingLevel = 'WppTracingLevel'        
    $reportingPath = 'HKLM:\Software\Microsoft\Windows Defender\Reporting'
    $etlparams = @{
        ArgumentList = @($PSScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
    }

    if (-not (Test-IsAdministrator)) {
        # non-administrator should be able to install.
        $etlparams.Credential = Get-Credential -UserName:Administrator -Message:"Administrator credential are required for starting an ETW session:"
        $etlparams.ComputerName = 'localhost'
        $etlparams.EnableNetworkAccess = $true
    }

    if (Test-Path -LiteralPath:$etlLog -PathType:leaf) {
        if (Test-Path -LiteralPath:"$PSScriptRoot\$logBase.prev.etl") {
            Remove-Item -LiteralPath:"$PSScriptRoot\$logBase.prev.etl" -ErrorAction:Stop
        }
        Rename-Item -LiteralPath:$etlLog -NewName:"$logBase.prev.etl" -ErrorAction:Stop
    }

    Invoke-Command @etlparams -ScriptBlock: {
        param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath);
        function Set-RegistryKey {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string] $LiteralPath,
                [Parameter(Mandatory)][string] $Name,
                [Parameter(Mandatory)][object] $Value)

            function Set-ContainerPath {
                [CmdletBinding()]
                param([Parameter(Mandatory)][string] $LiteralPath)
                if (!(Test-Path -LiteralPath:$LiteralPath -PathType:Container)) {
                    $parent = Split-Path -Path:$LiteralPath -Parent
                    Set-ContainerPath -LiteralPath:$parent
                    $leaf = Split-Path -Path:$LiteralPath -Leaf
                    $null = New-Item -Path:$parent -Name:$leaf -ItemType:Directory
                }
            }   
            Set-ContainerPath -LiteralPath:$LiteralPath
            Set-ItemProperty -LiteralPath:$LiteralPath -Name:$Name -Value:$Value
        }

        ## enable providers
        $providers = @(
            @{Guid = 'ebcca1c2-ab46-4a1d-8c2a-906c2ff25f39'; Flags = 0x0FFFFFFF; Level = 0xff; Name = "Services" },
            @{Guid = 'B0CA1D82-539D-4FB0-944B-1620C6E86231'; Flags = 0xffffffff; Level = 0xff; Name = 'EventLog' },
            @{Guid = 'A676B545-4CFB-4306-A067-502D9A0F2220'; Flags = 0xfffff; Level = 0x5; Name = 'setup' },
            @{Guid = '81abafee-28b9-4df5-bb2d-5b0be87829f5'; Flags = 0xff; Level = 0x1f; Name = 'mpwixca' },
            @{Guid = '68edb168-7705-494b-a746-9297abdc91d3'; Flags = 0xff; Level = 0x1f; Name = 'mpsigstub' },
            @{Guid = '2a94554c-2fbe-46d0-9fa6-60562281b0cb'; Flags = 0xff; Level = 0x1f; Name = 'msmpeng' },
            @{Guid = 'db30e9dc-354d-48b5-9dc0-aeaebc5c6b54'; Flags = 0xff; Level = 0x1f; Name = 'mpclient' },
            @{Guid = 'ac45fef1-612b-4066-85a7-dd0a5e8a7f30'; Flags = 0xff; Level = 0x1f; Name = 'mpsvc' },
            @{Guid = '5638cd78-bc82-608a-5b69-c9c7999b411c'; Flags = 0xff; Level = 0x1f; Name = 'mpengine' },
            @{Guid = '449df70e-dba7-42c8-ba01-4d0911a4aecb'; Flags = 0xff; Level = 0x1f; Name = 'mpfilter' },
            @{Guid = 'A90E9218-1F47-49F5-AB71-9C6258BD7ECE'; Flags = 0xff; Level = 0x1f; Name = 'mpcmdrun' },
            @{Guid = '0c62e881-558c-44e7-be07-56b991b9401a'; Flags = 0xff; Level = 0x1f; Name = 'mprtp' },
            @{Guid = 'b702d31c-f586-4fc0-bcf5-f929745199a4'; Flags = 0xff; Level = 0x1f; Name = 'nriservice' },
            @{Guid = '4bc60e5e-1e5a-4ec8-b0a3-a9efc31c6667'; Flags = 0xff; Level = 0x1f; Name = 'nridriver' },
            @{Guid = 'FFBD47B1-B3A9-4E6E-9A44-64864363DB83'; Flags = 0xff; Level = 0x1f; Name = 'mpdlpcmd' },
            @{Guid = '942bda7f-e07d-5a00-96d3-92f5bcb7f377'; Flags = 0xff; Level = 0x1f; Name = 'mpextms' },
            @{Guid = 'bc4992b8-a44c-4f70-834b-9d45df9b1824'; Flags = 0xff; Level = 0x1f; Name = 'WdDevFlt' }
        )
        Set-Content -LiteralPath:$wdprov -Value:"# {PROVIDER_GUID}<space>FLAGS<space>LEVEL" -Encoding:ascii
        $providers | ForEach-Object {
            # Any line that starts with '#','*',';' is commented out
            # '-' in front of a provider disables it.
            # {PROVIDER_GUID}<space>FLAGS<space>LEVEL
            Add-Content -LiteralPath:$wdprov -Value:("{{{0}}} {1} {2}" -f $_.Guid, $_.Flags, $_.Level) -Encoding:ascii
        }        
        
        try {
            & logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile *>$null
            ## this fails when 'Windows Defender' is already running.
            Set-RegistryKey -LiteralPath:$reportingPath -Name:$wppTracingLevel -Value:0 -ErrorAction:SilentlyContinue
            Trace-Message "Tracing session '$logBase' started."
        } catch {
            throw
        } finally {
            Remove-Item -LiteralPath:$wdprov -ErrorAction:Continue
        }
    }
}

try {
    $tempMsiLog = Join-Path -Path:$env:TEMP "$([guid]::NewGuid().Guid).log"
    [System.IO.FileStream] $msiStream = $null
    if ($null -ne $RemoveMMA) {
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
        $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
        if ($RemoveMMA -in $workspaces) {
            Trace-Message "Removing cloud workspace $($RemoveMMA.Guid)..." 
            $mma.RemoveCloudWorkspace($RemoveMMA)
            $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
            if ($workspaces.Count -gt 0) {
                $mma.ReloadConfiguration()
            } else {
                Stop-Service HealthService
            }
            Trace-Message "Workspace $($RemoveMMA.Guid) removed."
        } else {
            Exit-Install "Invalid workspace id $($RemoveMMA.Guid)" -ExitCode:$ERR_INVALID_PARAMETER
        }
    }
    
    $msiLog = "$PSScriptRoot\$logBase.log"    
    if ($log -and (Test-Path -LiteralPath:$msiLog -PathType:Leaf)) {
        if (Test-Path -LiteralPath:"$PSScriptRoot\$logBase.prev.log") {
            Remove-Item -LiteralPath:"$PSScriptRoot\$logBase.prev.log" -ErrorAction:Stop
        }
        Rename-Item -LiteralPath:$msiLog -NewName:"$PSScriptRoot\$logBase.prev.log"
    }
    
    ## The new name is 'Microsoft Defender for Endpoint' - to avoid confusions on Server 2016.
    $displayName = 'Microsoft Defender for (Windows Server|Endpoint)'
    $uninstallGUID = Get-UninstallGuid -DisplayName:$displayName
    
    if ($action -eq 'install') {
        $buildLabEx = Get-RegistryKey -LiteralPath:'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name:'BuildLabEx'
        Trace-Message "BuildLabEx: $buildLabEx"
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            $windefend = Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue
            $wdnissvc = Get-Service -Name:'WdNisSvc' -ErrorAction:SilentlyContinue
            $wdfilter = Get-Service -Name:'WdFilter' -ErrorAction:SilentlyContinue
            if ($windefend -and -not $wdnissvc -and -not $wdfilter) {
                ## workaround for ICM#278342470 (or VSO#37292177). Fixed on MOCAMP version 4.18.2111.150 or newer.
                if ($windefend.Status -eq 'Running') {
                    Exit-Install "Please reboot this computer to remove 'WinDefend' Service" -ExitCode:$ERR_PENDING_REBOOT
                } elseif ($windefend.Status -eq 'Stopped') {
                    Remove-Item -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Force -Recurse -ErrorAction:Stop
                    Exit-Install "Please restart this machine to complete 'WinDefend' service removal" -ExitCode:$ERR_PENDING_REBOOT
                } else {
                    Exit-Install -Message:"Unexpected WinDefend service status: $($windefend.Status)" -ExitCode:$ERR_UNEXPECTED_STATE
                }
            }

            ## SCEP is different on Server 2016.
            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Security Client"        
            if (Test-Path -LiteralPath:$path) {
                $displayName = (Get-ItemProperty -LiteralPath:$path -Name:'DisplayName').DisplayName
                # See camp\src\amcore\Antimalware\Source\AppLayer\Components\Distribution\Common\CmdLineParser.h
                $exitCode = Measure-Process -FilePath:"$env:ProgramFiles\Microsoft Security Client\Setup.exe" -ArgumentList:@('/u', '/s') -PassThru
                if (0 -eq $exitCode) {
                    Trace-Message "Uninstalling '$displayName' successful."
                } else {
                    Trace-Warning "Uninstalling '$displayName' exitcode: $exitCode."
                }
            }

            # Server2012R2 needs two KBs to be installed ... 
            function Install-KB {
                [CmdletBinding()]
                param([string] $Uri, [string]$KB, [scriptblock] $scriptBlock)
                $present = & $scriptBlock
                if ($present) {
                    return
                }
                $PreviousProgressPreference = $ProgressPreference               
                $outFile = Join-Path -Path:$env:TEMP $((New-Object System.Uri $Uri).Segments[-1])
                try {
                    $ProgressPreference = 'SilentlyContinue'
                    if (Get-HotFix -Id:$KB -ErrorAction:SilentlyContinue) {
                        Trace-Message "$KB already installed."
                        return
                    }
                    Trace-Message "Downloading $KB to $outFile"
                    Invoke-WebRequest -Uri:$Uri -OutFile:$outFile -ErrorAction:Stop
                    Trace-Message "Installing $KB"
                    $link = "https://support.microsoft.com/kb/{0}" -f $($KB.Substring(2))
                    $exitCode = Measure-Process -FilePath:$((Get-Command 'wusa.exe').Path) -ArgumentList:@($outFile, '/quiet', '/norestart') -PassThru
                    if (0 -eq $exitCode) {
                        Trace-Message "$KB installed."
                    } elseif (0x80240017 -eq $exitCode) {
                        #0x80240017 = WU_E_NOT_APPLICABLE = Operation was not performed because there are no applicable updates.
                        Exit-Install -Message:"$KB not applicable, please follow the instructions from $link" -ExitCode:$ERR_INSUFFICIENT_REQUIREMENTS
                    } elseif (0xbc2 -eq $exitCode) {
                        #0xbc2=0n3010,ERROR_SUCCESS_REBOOT_REQUIRED The requested operation is successful. Changes will not be effective until the system is rebooted
                        Exit-Install -Message "$KB required a reboot" -ExitCode:$ERR_PENDING_REBOOT
                    } else {
                        Exit-Install -Message:"$KB installation failed with exitcode: $exitCode. Please follow the instructions from $link" -ExitCode:$exitCode
                    }
                } catch {
                    ## not ok to ignore, MSI will simply fail with generic error 1603.
                    throw
                } finally {
                    $ProgressPreference = $PreviousProgressPreference
                    if (Test-Path -LiteralPath:$outFile -PathType:Leaf) {
                        Trace-Message "Removing $outFile"
                        Remove-Item -LiteralPath:$outFile -Force -ErrorAction:SilentlyContinue
                    }
                }
            }
            <## The minimum number of KBs to be applied (in this order) to a RTM Server 2012R2 image to have a successful install:
                KB2919442   prerequisite for KB2919355, https://www.microsoft.com/en-us/download/details.aspx?id=42153
                KB2919355   prerequisite for KB3068708, KB2999226 and KB3080149, https://www.microsoft.com/en-us/download/details.aspx?id=42334
                KB2999226   needed by WinDefend service, https://www.microsoft.com/en-us/download/details.aspx?id=49063
                KB3080149   telemetry dependency, https://www.microsoft.com/en-us/download/details.aspx?id=48637
                KB2959977   prerequisite for KB3045999,  https://www.microsoft.com/en-us/download/details.aspx?id=42529
                KB3068708   prerequisite for KB3045999,  https://www.microsoft.com/en-us/download/details.aspx?id=47362
                KB3045999   workaround for VSO#35611997, https://www.microsoft.com/en-us/download/details.aspx?id=46547

                To see the list of installed hotfixes run: 'Get-HotFix | Select-Object -ExpandProperty:HotFixID'
            #>
            ## ucrt dependency (needed by WinDefend service) - see https://www.microsoft.com/en-us/download/confirmation.aspx?id=49063
            Install-KB -Uri:'https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu' -KB:KB2999226 -ScriptBlock: {
                $ucrtbaseDll = "$env:SystemRoot\system32\ucrtbase.dll"
                if (Test-Path -LiteralPath:$ucrtbaseDll -PathType:Leaf) {
                    $verInfo = Get-FileVersion -File:$ucrtbaseDll
                    Trace-Message "$ucrtBaseDll version is $verInfo"
                    return $true
                }
                Trace-Warning "$ucrtbaseDll not present, trying to install KB2999226"
                return $false
            }
            ## telemetry dependency (needed by Sense service) - see https://www.microsoft.com/en-us/download/details.aspx?id=48637
            Install-KB -Uri:'https://download.microsoft.com/download/A/3/E/A3E82C15-7762-4104-B969-6A486C49DB8D/Windows8.1-KB3080149-x64.msu' -KB:KB3080149 -ScriptBlock: {
                $tdhDll = "$env:SystemRoot\system32\Tdh.dll"
                if (Test-Path -LiteralPath:$tdhDll -PathType:Leaf) {
                    $fileVersion = Get-FileVersion -File:$tdhDll
                    $minFileVersion = New-Object -TypeName:System.Version -ArgumentList:6, 3, 9600, 17958
                    if ($fileVersion -ge $minFileVersion) {
                        Trace-Message "$tdhDll version is $fileVersion"
                        return $true
                    }
                    Trace-Warning "$tdhDll version is $fileVersion (minimum version is $minFileVersion), trying to install KB3080149"
                    return $false
                }
                Trace-Warning "$tdhDll not present, trying to install KB3080149"
                return $false
            }
            ## needed by Sense - see VSO#35611997
            Install-KB -Uri:'https://download.microsoft.com/download/3/9/E/39EAFBBF-A801-4D79-B2B1-DAC4673AFB09/Windows8.1-KB3045999-x64.msu' -KB:KB3045999 -ScriptBlock: {
                $osVersion = Get-OSVersion
                $minNtVersion = New-Object -TypeName:System.Version -ArgumentList:6, 3, 9600, 17736
                if ($osVersion -ge $minNtVersion) {
                    Trace-Message "OsVersion is $osVersion"
                    return $true
                }
                Trace-Warning "Current ntoskrnl.exe version is $osVersion (minimum required is $minNtVersion), trying to install KB3045999"
                return $false
            }
        } elseif ($osVersion.Major -eq 10 -and $osVersion.Minor -eq 0 -and $osVersion.Build -lt 18362) {
            $defenderFeature = Get-WindowsOptionalFeature -Online -FeatureName:'Windows-Defender' -ErrorAction:Stop
            if ($defenderFeature.State -ne 'Enabled') {
                $defenderFeature = $defenderFeature | Enable-WindowsOptionalFeature -Online -NoRestart
            }
            if ($defenderFeature.RestartNeeded) {
                Exit-Install "Restart is required by 'Windows-Defender'" -ExitCode:$ERR_PENDING_REBOOT
            }

            if ($null -eq $uninstallGUID) {
                $codeSQUID = Get-CodeSQUID -ProductName:$displayName
                if ($null -ne $codeSQUID) {
                    ## Workaround for ICM#320556857
                    ## Previous version of this product was not properly uninstalled triggering an upgrade scenario
                    ## that fails because MSSecFlt.inf is missing.
                    Trace-Warning "Previously installed msi was not properly uninstalled(code:$codeSQUID)"
                    foreach ($subdir in 'Products', 'Features') {
                        $item = "HKCR:\Installer\$subdir\$codeSQUID"
                        if (Test-Path -LiteralPath:$item -PathType:Container) {
                            Rename-Item -LiteralPath:$item -NewName:"$codeSQUID~" -ErrorAction:Stop
                            Trace-Warning "$item renamed to $codeSQUID~"
                        } else {
                            Trace-Warning "$item not present"
                        }
                    }
                }
            }
            
            $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            if ($windefendStatus -ne 'Running') {
                ## try to start it using 'mpcmdrun wdenable' (best effort)
                $disableAntiSpyware = Get-RegistryKey -LiteralPath:'HKLM:\Software\Microsoft\Windows Defender' -Name:'DisableAntiSpyware'
                if ($null -ne $disableAntiSpyware -and 0 -ne $disableAntiSpyware) {
                    Trace-Warning "DisableAntiSpyware is set to $disableAntiSpyware (should be zero)"
                }
                Invoke-MpCmdRun -ArgumentList:@('WDEnable')
                $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            }

            # Server 2016 - Windows Defender is shipped with OS, need to check if inbox version is updatable and latest.
            # Expectations are that 'Windows Defender Features' are installed and up-to-date            
            if ($windefendStatus -eq 'Running') {
                $imageName = (Get-ItemPropertyValue -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
                $currentVersion = Get-FileVersion -File:$imageName
                if ($currentVersion -lt '4.10.14393.2515') {
                    Exit-Install 'Windows Defender platform update requirement not met. Please apply the latest cumulative update (LCU) for Windows first. Minimum required is https://support.microsoft.com/en-us/help/4457127' -ExitCode:$ERR_INSUFFICIENT_REQUIREMENTS
                }
                $previousProgressPreference = $Global:ProgressPreference
                $deleteUpdatePlatform = $false
                try {
                    $Global:ProgressPreference = 'SilentlyContinue'
                    $msiVersion = (Get-MsiFilesInfo -MsiPath:$msi).'MPCLIENT.DLL'.Version
                    $updatePlatformBaseName = if ($DevMode.IsPresent) { 'UpdatePlatformD.exe' } else { 'UpdatePlatform.exe' }
                    if ($currentVersion -lt $msiVersion) {
                        Trace-Message "Current platform version is $currentVersion, msiVersion is $msiVersion"
                        $updatePlatform = Join-Path -Path:$PSScriptRoot $updatePlatformBaseName
                        if (-not (Test-Path -LiteralPath:$updatePlatform -PathType:Leaf) -and -not $DevMode.IsPresent) {
                            ## Download $updatePlatformBaseName from $uri *only if* the UpdatePlatform is not present.
                            $uri = 'https://go.microsoft.com/fwlink/?linkid=870379&arch=x64'
                            Trace-Message "$updatePlatformBaseName not present under $PSScriptRoot"
                            $latestVersion = ([xml]((Invoke-WebRequest -UseBasicParsing -Uri:"$uri&action=info").Content)).versions.platform
                            if ($latestVersion -lt $msiVersion) {
                                Trace-Warning "Changing $msiVersion from $msiVersion to $latestVersion"
                                $msiVersion = $latestVersion
                            }
                            Trace-Message "Downloading latest $updatePlatformBaseName (version $latestVersion) from $uri"
                            $deleteUpdatePlatform = $true
                            Invoke-WebRequest -UseBasicParsing -Uri:$uri -OutFile:$updatePlatform
                        }
                        $updatePlatformVersion = Get-FileVersion -File:$updatePlatform
                        if ($updatePlatformVersion -lt $msiVersion) {
                            Exit-Install "Minimum required version is $msiVersion. $updatePlatform version is $updatePlatformVersion" -ExitCode:$ERR_INSUFFICIENT_REQUIREMENTS
                        }

                        $status = (Get-AuthenticodeSignature -FilePath:$updatePlatform).Status
                        if ($status -ne 'Valid') {
                            Exit-Install "Unexpected authenticode signature status($status) for $updatePlatform" -ExitCode:$ERR_CORRUPTED_FILE
                        }
                        ## make sure the right file was downloaded (or present in this directory)
                        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($updatePlatform)
                        if ($updatePlatformBaseName -ne $fileInfo.InternalName) {
                            Exit-Install "Unexpected file: $updatePlatform, InternalName='$($fileInfo.InternalName)' (expecting '$updatePlatformBaseName')" -ExitCode:$ERR_CORRUPTED_FILE
                        }                       
                        if ('Microsoft Malware Protection' -ne $fileInfo.ProductName) {
                            Exit-Install "Unexpected file: $updatePlatform, ProductName='$($fileInfo.ProductName)' (expecting 'Microsoft Malware Protection')" -ExitCode:$ERR_CORRUPTED_FILE
                        }

                        Trace-Message ("Running $updatePlatformBaseName (version {0})" -f (Get-FileVersion -File:$updatePlatform))
                        Measure-Process -FilePath:$updatePlatform
                        $imageName = (Get-ItemPropertyValue -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
                        $currentVersion = Get-FileVersion -File:$imageName
                        if ($currentVersion -lt $latestVersion) {
                            Exit-Install "Current version is $currentVersion, expected to be at least $latestVersion" -ExitCode:$ERR_INSUFFICIENT_REQUIREMENTS
                        }
                        Trace-Message "Current platform version is $currentVersion"
                    }
                } catch {
                    throw
                } finally {
                    $Global:ProgressPreference = $previousProgressPreference
                    if ($deleteUpdatePlatform) {
                        Remove-Item -LiteralPath:$updatePlatform -ErrorAction:SilentlyContinue
                        if (Test-Path -LiteralPath:$updatePlatform -PathType:Leaf) {
                            Trace-Warning "Could not delete $updatePlatform"
                        } else {
                            Trace-Message "$updatePlatform deleted"
                        }
                    }
                }
            } else {
                Exit-Install "'WinDefend' service is not running." -ExitCode:$ERR_UNEXPECTED_STATE
            }
        } else {
            Exit-Install "Unsupported OS version: $osVersion" -ExitCode:$ERR_UNSUPPORTED_DISTRO
        }
    }

    $onboardSense = Get-RegistryKey -LiteralPath:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
    if ($OffboardingScript.Length -gt 0 -and ($action -eq 'uninstall' -or $null -ne $uninstallGUID)) {
        if (2 -ne $onboardSense) {
            Exit-Install -Message:"Sense Service is not onboarded, nothing to offboard." -ExitCode:$ERR_NOT_ONBOARDED
        }
        Trace-Message "Invoking offboarding script $OffboardingScript"
        $scriptPath = if ($OffboardingScript.Contains(' ') -and -not $OffboardingScript.StartsWith('"')) {
            '"{0}"' -f $OffboardingScript
        } else {
            $OffboardingScript
        }
        $exitCode = Measure-Process -FilePath:$((Get-Command 'cmd.exe').Path) -ArgumentList:@('/c', $scriptPath) -PassThru
        if (0 -eq $exitCode) {
            Trace-Message "Offboarding successful."
            $onboardSense = Get-RegistryKey -LiteralPath:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
        } else {
            Exit-Install "Offboarding script returned $exitCode." -ExitCode:$exitCode
        }
        
        # SenseIR up to version 10.8045.22439.1011 leaks SenseIRTraceLogger ETW session, preventing a clean install/uninstall.
        # See VSO#36551957
        & logman.exe query "SenseIRTraceLogger" -ets *>$null
        if (0 -eq $LASTEXITCODE) {
            Trace-Warning "SenseIRTraceLogger still present, removing it!"
            & logman.exe stop -n "SenseIRTraceLogger" -ets *>$null
            if (0 -ne $LASTEXITCODE) {
                Trace-Warning "SenseIRTraceLogger could not be removed, exitCode=$LASTEXITCODE"
            }
        }
    }

    if ($action -eq 'uninstall') {
        foreach ($name in 'ConfigDefender', 'Defender') {
            $defender = Get-Module $name -ErrorAction:SilentlyContinue
            if ($defender) {
                Remove-Module $defender
                Trace-Message 'Defender module unloaded.'
                break
            }
        }
    } 
    
    if (2 -eq $onboardSense) {
        # all MSI operations (installing, uninstalling, upgrading) should be performed while Sense is offboarded.
        Exit-Install -Message:"Sense Service is onboarded, offboard before reinstalling(or use -OffboardingScript with this script)" -ExitCode:$ERR_NOT_OFFBOARDED
    }

    $argumentList = if ($action -eq 'install') {
        if (-not (Test-Path -LiteralPath:$msi -PathType:leaf)) {
            Exit-Install "$msi does not exist." -ExitCode:$ERR_MSI_NOT_FOUND
        } else {
            try {
                $msiStream = [System.IO.File]::OpenRead($msi)
                Trace-Message ("Handle {0} opened over {1}" -f $msiStream.SafeFileHandle.DangerousGetHandle(), $msi)
            } catch {
                ## Orca (https://docs.microsoft.com/en-us/windows/win32/msi/orca-exe) likes to keep a opened handle to $msi
                ## and if installation happens during this time  Get-AuthenticodeSignature will get an 'Unknown' status. 
                ## Same with msiexec.exe, so better check for this scenario here.
                Exit-Install "Cannot open $msi for read: $_.Exception" -ExitCode:$ERR_MSI_USED_BY_OTHER_PROCESS
            }
            $status = (Get-AuthenticodeSignature -FilePath:$msi).Status
            if ($status -ne 'Valid') {
                Exit-Install "Unexpected authenticode signature status($status) for $msi" -ExitCode:$ERR_CORRUPTED_FILE
            }
            Trace-Message "$($(Get-FileHash -LiteralPath:$msi).Hash) $msi"
        }
        if ($msi.Contains(' ')) { @('/i', "`"$msi`"") } else { @('/i', $msi) }
    } else {
        if ($null -eq $uninstallGUID) {
            Exit-Install "'$displayName' already uninstalled." -ExitCode:$ERR_MDE_NOT_INSTALLED
        }
        @('/x', $uninstallGUID)
    }

    if ($log) {
        $argumentList += '/lvx*+'
        $argumentList += if ($tempMsiLog.Contains(' ')) { "`"$tempMsiLog`"" } else { $tempMsiLog }
    }

    if (-not $UI.IsPresent) {
        $argumentList += '/quiet'
    }

    if ($Passive.IsPresent) {
        Trace-Message "Will force passive mode."
        $argumentList += 'FORCEPASSIVEMODE=1'
    }
    
    $exitCode = Measure-Process -FilePath:$((Get-Command 'msiexec.exe').Path) -ArgumentList:$argumentList -PassThru
    if (0 -eq $exitCode) {
        Trace-Message "$action successful."
    } else {
        Exit-Install "$action exitcode: $exitCode" -ExitCode:$exitCode
    }
    
    if ($action -eq 'install') {
        if ($null -ne $codeSQUID) {
            ## install succeeded, no need to keep around these 2 registry keys.
            foreach ($subdir in 'Products', 'Features') {
                $itemPath = "HKCR:\Installer\$subdir\$codeSQUID~"
                if (Test-Path -LiteralPath:$itemPath -PathType:Container) {
                    try {
                        Remove-Item -LiteralPath:$itemPath -Recurse -ErrorAction:Stop
                        Trace-Message "$itemPath recusively removed"
                    } catch {
                        Trace-Warning "Failed to remove $itemPath"
                    }
                }
            }
        }

        if ($OnboardingScript.Length) {
            Trace-Message "Invoking onboarding script $OnboardingScript"
            $scriptPath = if ($OnboardingScript.Contains(' ') -and -not $OnboardingScript.StartsWith('"')) {
                '"{0}"' -f $OnboardingScript
            } else {
                $OnboardingScript
            }
            $argumentList = @('/c', $scriptPath)
            
            $exitCode = Measure-Process -FilePath:$((Get-Command 'cmd.exe').Path) -ArgumentList:$argumentList -PassThru
            if (0 -eq $exitCode) {
                Trace-Message "Onboarding successful."
            } else {
                Trace-Warning "Onboarding script returned $exitCode"
            }
        }
    }
} catch {
    throw
} finally {
    if ($msiStream.CanRead) {
        Trace-Message ("Closing handle {0}" -f $msiStream.SafeFileHandle.DangerousGetHandle())
        $msiStream.Close()
    }
    if ($etl) {
        Invoke-Command @etlparams -ScriptBlock: {
            param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
            & logman.exe stop -n $logBase -ets *>$null
            Trace-Message "Tracing session '$logBase' stopped."
            Remove-ItemProperty -LiteralPath:$reportingPath -Name:$wppTracingLevel -ErrorAction:SilentlyContinue
        }
        Move-Item -LiteralPath:$tempFile -Destination:$etlLog -ErrorAction:Continue
        Trace-Message  "ETL file: '$etlLog'."
    }   

    if ($log -and (Test-Path -LiteralPath:$tempMsiLog -PathType:Leaf)) {
        Move-Item -LiteralPath:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Trace-Message "Msi log: '$msiLog'"
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.
# SIG # Begin signature block
# MIIlggYJKoZIhvcNAQcCoIIlczCCJW8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBv0coJipIaxLAt
# sLcbFf3ZJ3RVS4AdocC5MXlVAsctiqCCC14wggTrMIID06ADAgECAhMzAAAJaWnl
# VutOg/ZMAAAAAAlpMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIyMDUwNTIyMDAyN1oXDTIzMDUwNDIyMDAyN1owcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpucHUMbAq
# 9TX7bb9eT5HgeUEAkCQqx8db9IGteLWtjh7NXNnUoxW79fDID+6GZihupXDFRFP7
# pD+iewhd91gfBNLczlB1hMeaggJ988VzxWpMNgQ3fYpeJDEwMdhmExRJyZEIKYFH
# Dy/Bh5eykRIQmbiUi/r9+kj0W9hCMnuKRn2aXLee2YONt75g9vHH83+K+spbd04Y
# ECV7o416V9cN/T5Sff4V8Bfx3q5B4wS8eWrTYV2CYwUFJaK4RSyuPIbBwxRuZ4Fk
# uhonXnXHkaqQeMnd8PiFLppsga9wBhCDgmfamObmxwzl7gnl6jy0sNc7/3qMeWa2
# F/UKhk8suiwNAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUP5G9CxyPFlyBsy62z8QNx41WZv0wUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDcwMDM5MB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBAB4ai/kHW6cL86Rj+whuX/0UERNcW/Ls
# KHite2ZfF46eYv73CyuLFzuCpc9Kuo41WjQx1Sl/pTeSPx57lJHQRmeVK+yYvm24
# 8LsVmLUiTZC1yRQ+PLvNfmwf26A3Bjv2eqi0xSKlRqYNcX1UWEJYBrxfyK+MWEtd
# 84bwd8dnflZcPd4xfGPCtR9FUuFVjf+yXrSPUnD3rxT9AcebzU2fdqMGYHODndNz
# ZmoroyIYPE7bIchKPa0WeQwT7pGf5FZdWCo/M8ym2qzIKhFGyG67cI5ZTErj4nvv
# s5NSLMP0Og+6TQ5mRgVCwZyRknQ/1qLuuZNDd0USoHmOVTtp8tqqOiAwggZrMIIE
# U6ADAgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0y
# NTA3MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTk
# sZ/ByJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwd
# lKsZv6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaK
# x3NpdlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAig
# g9cjH/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5Me
# KOBzbdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB
# 4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNk
# lMPYVqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAk
# JOP53JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBi
# QbpIdIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPdu
# QUdSHLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUU
# I2pBf9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gb
# Dmt25LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDA
# jtGIT5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDK
# rWQQ6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4
# n2KC7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr
# 9FrJlc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H
# 7lah7Ou1TIUxghl6MIIZdgIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACWlp5VbrToP2TAAAAAAJaTANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgkMl4B2Luh+RmTRKlNcr7y79wjs/yKV9blNBMZL27
# NPwwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBOJKXauvA+
# 8SFUgvGOF12ePPhRi6Bo++WCuXYsNtLGfnpKOsLPMD/SfL/rwouytzDTPimVQ1LD
# EG1GugIIlD2o2pPDMBokXFzhumFzVRltmgy263JXXV/U8NRZkyaFhvaACVUe4DME
# rASU1s/1cJT9EscLxC+TERrcsLNIjCrOAgpCCHKXmgjdt+dn/78gpzJsNvD/MZoR
# z9JA50zJkQMtPYiKggUpoM5PO5FRf7qr4S4w1MRJhjEjyd791PHNNm7tASBxpReg
# Zp11I8Zg3Ago9O+5CnMpgBjbOzfTDy4YlYpGviKyUdAMrWLslSKb5kMh3Myg72Al
# MS7O2T9F6H5SoYIXCTCCFwUGCisGAQQBgjcDAwExghb1MIIW8QYJKoZIhvcNAQcC
# oIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIB
# RASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIIu39wX4
# raexCf1cPM9FeeBZruxD5P/51H7lZTyqlyboAgZi/rqHsdwYEzIwMjIwODIyMDcz
# ODEyLjc4NFowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVwwggcQMIIE
# +KADAgECAhMzAAABsKHjgzLojTvAAAEAAAGwMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMwMjE4NTE0MloXDTIzMDUx
# MTE4NTE0Mlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAJzGbTsM19KCnQc5RC7VoglySXMKLut/yWWPQWD6VAlJgBexVKx2
# n1zgX3o/xA2ZgZ/NFGcgNDRCJ7mJiOeW7xeHnoNXPlg7EjYWulfk3oOAj6a7O15G
# vckpYsvLcx+o8Se8CrfIb40EJ8W0Qx4TIXf0yDwAJ4/qO94dJ/hGabeJYg4Gp0G0
# uQmhwFovAWTHlD1ci+sp36AxT9wIhHqw/70tzMvrnDF7jmQjaVUPnjOgPOyFWZiV
# r7e6rkSl4anT1tLv23SWhXqMs14wolv4ZeQcWP84rV2Frr1KbwkIa0vlHjlv4xG9
# a6nlTRfo0CYUQDfrZOMXCI5KcAN2BZ6fVb09qtCdsWdNNxB0y4lwMjnuNmx85FNf
# zPcMZjmwAF9aRUUMLHv626I67t1+dZoVPpKqfSNmGtVt9DETWkmDipnGg4+BdTpl
# vgGVq9F3KZPDFHabxbLpSWfXW90MZXOuFH8yCMzDJNUzeyAqytFFyLZir3j4T1Gx
# 7lReCOUPw1puVzbWKspV7ModZjtN/IUWdVIdk3HPp4QN1wwdVvdXOsYdhG8kgjGy
# AZID5or7C/75hyKQb5F0Z+Ee04uY9K+sDZ3l3z8TQZWAfYurbZCMWWnmJVsu5V4P
# R5PO+U6D7tAtMvMULNYibT9+sxVZK/WQer2JJ9q3Z7ljFs4lgpmfc6AVAgMBAAGj
# ggE2MIIBMjAdBgNVHQ4EFgQUOt8BJDcBJm4dy6ASZHrXIEfWNj8wHwYDVR0jBBgw
# FoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1T
# dGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEF
# BQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNy
# b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/
# BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEA3XPi
# h5sNtUfAyLnlXq6MZSpCh0TF+uG+nhIJ44//cMcQGEViZ2N263NwvrQjCFOni/+o
# xf76jcmUhcKWLXk9hhd7vfFBhZZzcF5aNs07Uligs24pveasFuhmJ4y82OYm1G1O
# RYsFndZdvF//NrYGxaXqUNlRHQlskV/pmccqO3Oi6wLHcPB1/WRTLJtYbIiiwE/u
# TFEFEL45wWD/1mTCPEkFX3hliXEypxXzdZ1k6XqGTysGAtLXUB7IC6CH26YygKQu
# XG8QjcJBAUG/9F3yNZOdbFvn7FinZyNcIVLxld7h0bELfQzhIjelj+5sBKhLcaFU
# 0vbjbmf0WENgFmnyJNiMrL7/2FYOLsgiQDbJx6Dpy1EfvuRGsdL5f+jVVds5oMaK
# rhxgV7oEobrA6Z56nnWYN47swwouucHf0ym1DQWHy2DHOFRRN7yv++zes0GSCOjR
# RYPK7rr1Qc+O3nsd604Ogm5nR9QqhOOc2OQTrvtSgXBStu5vF6W8DPcsns53cQ4g
# dcR1Y9Ng5IYEwxCZzzYsq9oalxlH+ZH/A6J7ZMeSNKNkrXPx6ppFXUxHuC3k4mzV
# yZNGWP/ZgcUOi2qV03m6Imytvi1kfGe6YdCh32POgWeNH9lfKt+d1M+q4IhJLmX0
# E2ZZICYEb9Q0romeMX8GZ+cbhuNsFimJga/fjjswggdxMIIFWaADAgECAhMzAAAA
# FcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5
# MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwH
# B9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0T
# z3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5
# YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5T
# z9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoF
# VZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGp
# F1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+Autuq
# fjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhz
# PUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrX
# Y28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFd
# Etsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacau
# e7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYB
# BAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsG
# AQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVw
# b3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRf
# MjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb
# 4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGh
# lBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB
# 2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIR
# XT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixr
# e24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZM
# cm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFX
# SVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d
# 0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFR
# hLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq
# 8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJt
# pQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAp4vkN3fD5FNBVYZklZeS/JFPBiggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
# AAIFAOatLX4wIhgPMjAyMjA4MjIwMjE3MzRaGA8yMDIyMDgyMzAyMTczNFowdDA6
# BgorBgEEAYRZCgQBMSwwKjAKAgUA5q0tfgIBADAHAgEAAgIdXDAHAgEAAgIRTzAK
# AgUA5q5+/gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBACLnoXoMK8a0grjs
# z0wTRM6rqtEyU5/zP+9mM3C7S7tRAKFVlpLXbPqmBH8Pxfhcr/vrUkqBShntkTzs
# tcwGRIqn7+waElu4UEGFO776OVjy9H7I7ooMloptsg3GLy8rq+NvoLFbR19JO6BV
# AenvBVUkAbXRx4ObceuCiHeGwxzCMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAGwoeODMuiNO8AAAQAAAbAwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgUnFKjic4MO5e9QymkcLJBAK9RONT2UL61DEH73cKlx0wgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCDNBgtDd8uf9KTjGf1G67IfKmcNFJmeWTd6ilAy
# 5xWEoDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# sKHjgzLojTvAAAEAAAGwMCIEILf8jL9uLIB5lweshOeNEDaaS3OkkVNKzXtGSPGe
# OA0pMA0GCSqGSIb3DQEBCwUABIICADFnt84VvdeZmozblggUslEBfNRCifKOMPYl
# 2nbYsqLrKEN0I79QmCSsGHVmPkML+1CmLoJN5lJVArhsz90aJ+iJMaazMV/b8FO7
# 5F+s1Cib6IhUEU4P+eRrZj1RVJKpmYqKd1r5djcZ+WClU0c35E/0GlQS9dldvCJL
# Vq//Egdli3YNZTicZgbA+BWQVZdrfi0JoSe9hoIBk+tFHRQDBtsGeDAGiAJ+nKYg
# gZW7z+nj7Yer4CrotjIJxlSs9UyZm5nhnFlgplQQBEygkgtU+f+vaewC1DspqCqP
# WmQ0HR55C0xkt5q7qH5BacOb8Hh/1QMD2oclbEXO38ICyUg54mMO78KhDUS2ybw+
# aMyOFogkUKXOys6K/v4ezhoLKD0cYsP2itg3SHvGuVPaCErmkzRZVeD/dwXfy9aN
# iC+nhkRNg8hE6bzwkvHdOaouq4OXFs1u/Myipxcx3VPmZcvpjcDHnWQnf5mfBukt
# Dznqc38g8qrTDp72/CEWKrCAICt71Mb53ZXwEGoHZHuqrqDHxazf5/FiXtmS4DcG
# wfIxQCSjXHaSFs3NcNQBQ9jY9a/CDhqpMMZNmh3FSLMDpJPiKCJ3XoAU3CRHRhaT
# gLBWfl4Bjsk3xXGJCuUJX5nuzsQTuc3hcRh+IDLF76rCwY9YbWgBotNhXBOUilLY
# UNC4avRk
# SIG # End signature block
