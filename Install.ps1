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
        [ValidateScript( { Test-Path -Path:$_ -PathType:Leaf })]
        [string] $FilePath,

        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,
        [switch] $PassThru,
        [ValidateScript( { Test-Path -Path:$_ -PathType:Container })]
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
            $commandLine = $(Split-Path $FilePath -Leaf)
            if ($ArgumentList) {
                $commandLine += " $ArgumentList"
            }
            $message = if (0 -eq $exitCode) {
                "Command `"$commandLine`" run for $runningTime"
            } else {
                "Command `"$commandLine`" failed with error 0x{0:x} after $runningTime" -f $exitCode
            }
            Trace-Message $message -SkipFrames:$SkipFrames           
            if (-not $PassThru -and 0 -ne $exitCode) {
                exit $exitCode
            }
        } -ArgumentList:$ArgumentList, (2 + $SkipFrames)
    } catch {
        throw
    } finally {
        Remove-Item -Path:$startParams.RedirectStandardError.FullName -Force -ErrorAction:SilentlyContinue
        Remove-Item -Path:$startParams.RedirectStandardOutput.FullName -Force -ErrorAction:SilentlyContinue
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

function Get-UninstallGuid {
    [CmdletBinding()]
    param (
        [string] $DisplayName
    )
    ## guids are regenerated every time we change .wx{i,s} files
    $result = @(Get-ChildItem -Path:'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
        ForEach-Object {
            Get-ItemProperty $_.PSPath
        } | 
        Where-Object {
            $_.DisplayName -match $DisplayName -and $_.PSChildName -match '^{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}}$'
        } | 
        Select-Object -ExpandProperty:PSChildName)
    if ($result.Count -eq 1) {
        return $result[0]
    }
    return $null
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
        if (-not (Test-Path -Path:$OnboardingScript -PathType:Leaf)) {
            Exit-Install -Message:"$OnboardingScript does not exist" -ExitCode:$ERR_ONBOARDING_NOT_FOUND
        }       
        ## validate it is an "onboarding" script.
        $on = Get-Content -Path:$OnboardingScript | Where-Object {
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
        if (-not (Test-Path -Path:$OffboardingScript -PathType:Leaf)) {
            Exit-Install -Message:"$OffboardingScript does not exist" -ExitCode:$ERR_OFFBOARDING_NOT_FOUND
        }

        $off = Get-Content -Path:$OffboardingScript | Where-Object {
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
    param([Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Name)

    $k = Get-ItemProperty -Path:$Path -Name:$Name -ErrorAction SilentlyContinue
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
        FilePath   = Join-Path -Path:$(Get-RegistryKey -Path:'HKLM:\SOFTWARE\Microsoft\Windows Defender' -Name:'InstallLocation') 'MpCmdRun.exe'
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
Set-Content -Path:$tempFile -Value:'' -ErrorAction:SilentlyContinue
if (-not (Test-Path -Path:$tempFile -PathType:Leaf)) {
    Exit-Install "Cannot create $tempFile. Is $PSScriptRoot writable?" -ExitCode:$ERR_DIRECTORY_NOT_WRITABLE
} else {
    Remove-Item -Path:$tempFile -ErrorAction:SilentlyContinue
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

    if (Test-Path -Path:$etlLog -PathType:leaf) {
        if (Test-Path -Path:"$PSScriptRoot\$logBase.prev.etl") {
            Remove-Item -Path:"$PSScriptRoot\$logBase.prev.etl" -ErrorAction:Stop
        }
        Rename-Item -Path:$etlLog -NewName:"$logBase.prev.etl" -ErrorAction:Stop
    }

    Invoke-Command @etlparams -ScriptBlock: {
        param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath);
        function Set-RegistryKey {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string] $Path,
                [Parameter(Mandatory)][string] $Name,
                [Parameter(Mandatory)][object] $Value)

            function Set-ContainerPath {
                [CmdletBinding()]
                param([Parameter(Mandatory)][string] $Path)
                if (!(Test-Path -Path:$Path -PathType:Container)) {
                    $parent = Split-Path -Path:$Path -Parent
                    Set-ContainerPath -Path:$parent
                    $leaf = Split-Path -Path:$Path -Leaf
                    $null = New-Item -Path:$parent -Name:$leaf -ItemType:Directory
                }
            }   
            Set-ContainerPath -Path:$Path
            Set-ItemProperty -Path:$Path -Name:$Name -Value:$Value
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
            @{Guid = '942bda7f-e07d-5a00-96d3-92f5bcb7f377'; Flags = 0xff; Level = 0x1f; Name = 'mpextms' }
        )
        Set-Content -Path:$wdprov -Value:"# {PROVIDER_GUID}<space>FLAGS<space>LEVEL" -Encoding:ascii
        $providers | ForEach-Object {
            # Any line that starts with '#','*',';' is commented out
            # '-' in front of a provider disables it.
            # {PROVIDER_GUID}<space>FLAGS<space>LEVEL
            Add-Content -Path:$wdprov -Value:("{{{0}}} {1} {2}" -f $_.Guid, $_.Flags, $_.Level) -Encoding:ascii
        }        
        
        try {
            & logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile *>$null
            ## this fails when 'Windows Defender' is already running.
            Set-RegistryKey -Path:$reportingPath -Name:$wppTracingLevel -Value:0 -ErrorAction:SilentlyContinue
            Trace-Message "Tracing session '$logBase' started."
        } catch {
            throw
        } finally {
            Remove-Item -Path:$wdprov -ErrorAction:Continue
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
    if ($log -and (Test-Path -Path:$msiLog -PathType:Leaf)) {
        if (Test-Path -Path:"$PSScriptRoot\$logBase.prev.log") {
            Remove-Item -Path:"$PSScriptRoot\$logBase.prev.log" -ErrorAction:Stop
        }
        Rename-Item -Path:$msiLog -NewName:"$PSScriptRoot\$logBase.prev.log"
    }
        
    if ($action -eq 'install') {
        $buildLabEx = Get-RegistryKey -Path:'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name:'BuildLabEx'
        Trace-Message "BuildLabEx: $buildLabEx"
        $hotfix = @(Get-HotFix | Sort-Object -Property:InstalledOn)
        Trace-Message "There are $($hotFix.Count) KBs installed."
        if ($hotfix.Count -gt 0) {
            $lastHotfix = $hotfix[-1]
            Trace-Message "$($lastHotFix.HotFixID) was installed on $($lastHotfix.InstalledOn)"
        }
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            $windefend = Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue
            $wdnissvc = Get-Service -Name:'WdNisSvc' -ErrorAction:SilentlyContinue
            $wdfilter = Get-Service -Name:'WdFilter' -ErrorAction:SilentlyContinue
            if ($windefend -and -not $wdnissvc -and -not $wdfilter) {
                ## workaround for ICM#278342470. Fixed on MOCAMP version 4.18.2111.150 or newer.
                if ($windefend.Status -eq 'Running') {
                    Exit-Install "Please reboot this computer to remove 'WinDefend' Service" -ExitCode:$ERR_PENDING_REBOOT
                } elseif ($windefend.Status -eq 'Stopped') {
                    Remove-Item -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Force -Recurse -ErrorAction:Stop
                    Exit-Install "Please restart this machine to complete 'WinDefend' service removal" -ExitCode:$ERR_PENDING_REBOOT
                } else {
                    Exit-Install -Message:"Unexpected WinDefend service status: $($windefend.Status)" -ExitCode:$ERR_UNEXPECTED_STATE
                }
            }

            ## SCEP is different on Server 2016.
            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Security Client"        
            if (Test-Path -Path:$path) {
                $displayName = (Get-ItemProperty -Path:$path -Name:'DisplayName').DisplayName
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
                        #0xbc2=0n3010,ERROR_SUCCESS_REBOOT_REQUIRED	The requested operation is successful. Changes will not be effective until the system is rebooted
                        Exit-Install -Message "$KB required a reboot" -ExitCode:$ERR_PENDING_REBOOT
                    } else {
                        Exit-Install -Message:"$KB installation failed with exitcode: $exitCode. Please follow the instructions from $link" -ExitCode:$exitCode
                    }
                } catch {
                    ## not ok to ignore, MSI will simply fail with generic error 1603.
                    throw
                } finally {
                    $ProgressPreference = $PreviousProgressPreference
                    if (Test-Path -Path:$outFile -PathType:Leaf) {
                        Trace-Message "Removing $outFile"
                        Remove-Item -Path:$outFile -Force -ErrorAction:SilentlyContinue
                    }
                }
            }
            ## ucrt dependency (needed by WinDefend service) - see https://www.microsoft.com/en-us/download/confirmation.aspx?id=49063
            Install-KB -Uri:'https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu' -KB:KB2999226 -ScriptBlock: {
                $ucrtbaseDll = "$env:SystemRoot\system32\ucrtbase.dll"
                if (Test-Path -Path:$ucrtbaseDll -PathType:Leaf) {
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
                if (Test-Path -Path:$tdhDll -PathType:Leaf) {
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
        } elseif ($osVersion.Major -eq 10 -and $osVersion.Minor -eq 0 -and $osVersion.Build -lt 18362) {
            $defenderFeature = Get-WindowsOptionalFeature -Online -FeatureName:'Windows-Defender-Features' -ErrorAction:Stop
            if ($defenderFeature.State -ne 'Enabled') {
                $defenderFeature = $defenderFeature | Enable-WindowsOptionalFeature -Online -NoRestart
            }
            if ($defenderFeature.RestartNeeded) {
                Exit-Install "Restart is required by 'Windows-Defender-Features'" -ExitCode:$ERR_PENDING_REBOOT
            }

            $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            if ($windefendStatus -ne 'Running') {
                ## try to start it using 'mpcmdrun wdenable' (best effort)
                $disableAntiSpyware = Get-RegistryKey -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'DisableAntiSpyware'
                if ($null -ne $disableAntiSpyware -and 0 -ne $disableAntiSpyware) {
                    Trace-Warning "DisableAntiSpyware is set to $disableAntiSpyware (should be zero)"
                }
                Invoke-MpCmdRun -ArgumentList:@('WDEnable')
                $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            }

            # Server 2016 - Windows Defender is shipped with OS, need to check if inbox version is updatable and latest.
            # Expectations are that 'Windows Defender Features' are installed and up-to-date            
            if ($windefendStatus -eq 'Running') {
                $imageName = (Get-ItemPropertyValue -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
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
                        if (-not (Test-Path -Path:$updatePlatform -PathType:Leaf) -and -not $DevMode.IsPresent) {
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
                        $imageName = (Get-ItemPropertyValue -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
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
                        Remove-Item -Path:$updatePlatform -ErrorAction:SilentlyContinue
                        if (Test-Path -Path:$updatePlatform -PathType:Leaf) {
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

    ## The new name is 'Microsoft Defender for Endpoint' - to avoid confusions on Server 2016.
    $displayName = 'Microsoft Defender for (Windows Server|Endpoint)'
    $uninstallGUID = Get-UninstallGuid -DisplayName:$displayName
    $onboardSense = Get-RegistryKey -Path:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
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
            $onboardSense = Get-RegistryKey -Path:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
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
        if (-not (Test-Path -Path:$msi -PathType:leaf)) {
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
            Trace-Message "$($(Get-FileHash -Path:$msi).Hash) $msi"
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
    
    if ($action -eq 'install' -and $OnboardingScript.Length) {
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
            Remove-ItemProperty -Path:$reportingPath -Name:$wppTracingLevel -ErrorAction:SilentlyContinue
        }
        Move-Item -Path:$tempFile -Destination:$etlLog -ErrorAction:Continue
        Trace-Message  "ETL file: '$etlLog'."
    }   

    if ($log -and (Test-Path -Path:$tempMsiLog -PathType:Leaf)) {
        Move-Item -Path:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Trace-Message "Msi log: '$msiLog'"
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.
# SIG # Begin signature block
# MIIleQYJKoZIhvcNAQcCoIIlajCCJWYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDOyF8UEDnL8TU6
# y81QRHL7rtUfL0OqAthyXTx5msJZn6CCC14wggTrMIID06ADAgECAhMzAAAI/yN0
# 5bNiDD7eAAAAAAj/MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIxMDkwOTE5MDUxNloXDTIyMDkwMTE5MDUxNlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XnnM3dQr
# TkdEfd2ofYS42n2ZaluJCuT4F9PWFdlYA482HzK5e+7TSWW4AWxdYIM1qGM4fDRr
# 7tFBF+T6sChm9RFlnHsYEOovf0T62DEQuOUIleyAuq8MgtrV4X2GOiMvIYsoYFIQ
# cQpCbeHAXFFniWwJOG7sEZe0wWvxImHKot1//FPG/dR3HMZhXnAFWlXuJ6SAQOqY
# E4wF9x5Yl/1nAxjp+QbwR75w2vHYgrdZhvGMF5jrLJJOr+UtrrINYi2/Hs50XFHN
# 6nmh4iGjjUlRaFR93M9OepSDVIM6gEBZYiO0X/iR1w/B6s0tYs8fQgkc+jAcGVTt
# IRfNEydMVtBRAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUNBYlRvj/2BU45L0EYOW4Irw3QbowUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDY3NjAwMB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBADGfbGe9r+UZf8Qyfwku39aesTNARnzn
# wh17YDoFuqmdLT1A4SYEqnvl7xE4iGjvbV+jQjnkkyIA1B2ZOuhMEFIfdmtFkD0p
# ENenaq3Kx5EBQ3bb5jOmckp8UmcJ2Ej2XF7ZwYv2qcxNUZLE2fcl0B3INjXGGYP1
# nNYdheBa9z9tbOv/KRYxUQ1/od+vzHGPuypV/RQKIq6GnO0m7GkYe5HEn4ROn2KC
# 7xHnTIYH69EjONUt0zBtjgTb6l66TxcuORzOffGpkdmnY3TOwkJQGuPNIRGsUZpS
# KrA6s9EGC9wXYQwZqsNt5Hdawzx92CLMVjfkNP4BjJ26+1ovK6/P2xMwggZrMIIE
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
# 7lah7Ou1TIUxghlxMIIZbQIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACP8jdOWzYgw+3gAAAAAI/zANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgXhEDEk7Z/45OacGK6fLAbgvUBgLW+uPtKXXPtXhm
# cRgwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBHrPN2QX9Y
# f7eDt6gyIAZ/RJO/wiSNB8Sj6peVZIWgPIvUKA4HzKMUv19z7d2SZwtqzmCgHbtf
# hJjyVyFe+w7xKkJDUbI4NbZ5xKMJwFqWTETqlR6R5WtnajkYSOUDkZ2ob7ZRUi6b
# gINFOgTeCChJssa9Xmxpy3UuRMyDJKZPiNx84/WthI9cgwn/7vaiwNOhrsyapPtH
# bztnZ957XXZUElEuYH4+l8ahtiBgpqPZBQ2NKZf86G1yqvUYrobHG+aFr2VLB7dx
# OppTaFsdM591uPE6WLTPqzFPZH84nvmd/jq8aMjiUX3aYs2iQ3okP5MUsGL1PEbj
# e5cyoIMuIYG4oYIXADCCFvwGCisGAQQBgjcDAwExghbsMIIW6AYJKoZIhvcNAQcC
# oIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIB
# QASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIPk1KVhH
# 5wH1QFG7Tuf5m//cEOoV5n9Mv8ec6hG0veBiAgZigqaOUgMYEzIwMjIwNjIxMTIw
# ODQwLjY3NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0oAMC
# AQICEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkwNTE2WhcNMjMwMjI4MTkw
# NTE2WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
# A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC4E/lXXKMsy9rVa2a8bRb0Ar/Pj4+bKiAgMgKayvCMFn3ddGof8eWFgJWp5JdK
# jWjrnmW1r9tHpcP2kFpjXp2Udrj55jt5NYi1MERcoIo+E29XuCwFAMJftGdvsWea
# /OTQPIFsZEWqEteXdRncyVwct5xFzBIC1JWCdmfc7R59RMIyvgWjIz8356mweowk
# OstN1fe53KIJ8flrYILIQWsNRMOT3znAGwIb9kyL54C6jZjFxOSusGYmVQ+Gr/qZ
# QELw1ipx9s5jNP1LSpOpfTEBFu+y9KLNBmMBARkSPpTFkGEyGSwGGgSdOi6BU6FP
# K+6urZ830jrRemK4JkIJ9tQhlGcIhAjhcqZStn+38lRjVvrfbBI5EpI2NwlVIK2i
# bGW7sWeTAz/yNPNISUbQhGAJse/OgGj/1qz/Ha9mqfYZ8BHchNxn08nWkqyrjrKi
# cQyxuD8mCatTrVSbOJYfQyZdHR9a4vgyGeZEXBYQNAlIuB37QCOAgs/VeDU8M4dc
# /IlrTyC0uV1SS4Gk8zV+5X5eRu+XORN8FWqzI6k/9y6cWwOWMK6aUN1XqLcaF/sm
# 9rX84eKW2lhDc3C31WLjp8UOfOHZfPuyy54xfilnhhCPy4QKJ9jggoqqeeEhCEfg
# DYjy+PByV/e5HDB2xHdtlL93wltAkI3aCxo84kVPBCa0OwIDAQABo4IBNjCCATIw
# HQYDVR0OBBYEFI26Vrg+nGWvrvIh0dQPEonENR0QMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAHGzWh29ibBNro3n
# s8E3EOHGsLB1Gzk90SFYUKBilIu4jDbR7qbvXNd8nnl/z5D9LKgw3T81jqy5tMiW
# p+p4jYBBk3PRx1ySqLUfhF5ZMWolRzW+cQZGXV38iSmdAUG0CpR5x1rMdPIrTczV
# UFsOYGqmkoUQ/dRiVL4iAXJLCNTj4x3YwIQcCPt0ijJVinPIMAYzA8f99Bbeisky
# I0BHGAd0kGUX2I2/puYnlyS8toBnANjh21xgvEuaZ2dvRqvWk/i1XIlO67au/XCe
# MTvXhPOIUmq80U32Tifw3SSiBKTyir7moWH1i7H2q5QAnrBxuyy//ZsDfARDV/At
# mj5jr6ATfRHDdUanQpeoBS+iylNU6RARu8g+TMCu/ZndZmrs9w+8galUIGg+GmlN
# k07fXJ58Oc+qFqgNAsNkMi+dSzKkWGA4/klJFn0XichXL8+t7KOayXKGzQja6Cdt
# CjisnyS8hbv4PKhaeMtf68wJWKKOs0tt2AJfYC5vSbH9ck8BGj2e/yQXEZEu88L5
# /fHK5XUk/IKXx3zaLkxXTSZ43Ea/WKXVBzMasHZ3Pmny0moEekAXx1UhLNNYv4Vu
# m33VirxSB6r/GKQxFSHu7yFfrWQpYyyDH119TmhAedS8T1VabqdtO5ZP2E14TK82
# Vyxy3xEPelOo4dRIlhm7XY6k9B68MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYt
# OUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUAku/zYujnqapN6BJ9MJ5jtgDrlOuggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOZb8K0wIhgP
# MjAyMjA2MjExNTI0MjlaGA8yMDIyMDYyMjE1MjQyOVowdzA9BgorBgEEAYRZCgQB
# MS8wLTAKAgUA5lvwrQIBADAKAgEAAgIOPQIB/zAHAgEAAgITcjAKAgUA5l1CLQIB
# ADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQow
# CAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAB2B1a+VaivU9Hn2ad15vEzBXykp
# 4+tc5OCi2ggP9xXF+j8Vnjyn23WSFzcRekiQXP0rZMz9yayEuojqLsim8pV4Or0O
# 5OBhEri1dqLe43KEHhYAbdu+gmT5aPJIPV7jd5BARGfWona6ot8L3UaOSknXHf5r
# RzjncurDbANdFQYeMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJYIZIAWUDBAIBBQCgggFK
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgFirA
# NWy/TX3/QYd2csRMUP/X/YA7mrjrCyIYKHMJkH4wgfoGCyqGSIb3DQEJEAIvMYHq
# MIHnMIHkMIG9BCBmfWn58qKN7WWpBTYOrUO1BSCSnKPLC/G7wCOIc2JsfjCBmDCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABmciPr622fb6L
# AAEAAAGZMCIEIMEC/935bhT2P9QMcg8NKOM61NHN+KjWcSa1OeUz5rslMA0GCSqG
# SIb3DQEBCwUABIICADCci1U/GhveWCchqutdf9BISZ7FAWRUgF3truC78STexE0C
# M4zQeNz3FFnTDxVPNKEtRlX3K4ylxjmMwj28gWyDBnsYgvyV7PaT5HiTxgoXONEZ
# 8d6xLvK4oTaRIAwbnV28pTvpQL+/8mXyYfMBf4IZgaONfZjHV3uctg4nbVCOixf4
# 2CzM3McPPweyu+Twl1FUYF1jUs7EMJ4ojTUuNZXaKb4gJRNd076Ut1zzlDxbkbck
# kZBl3MkR0CRD/eS0rwWgoKw2HnILi1kP9UQH5fV3rvkk200lrHH7viswFLDFPCsF
# lCaRTSt20UBL9NzXjAZBxeSf/NH2MyF75M4LGNWlJNchYOSfsxeSoDsr2GSusFDD
# CjVubmz8Oi45H+2JottkvI9wVwyZxb69UF3k8db4OvcjWVzqb5OTeFdoc07oN0O5
# fDuFRmytf8jCCF37b0TFr2IN0gSjw6Oh2zg/4eO1QSnaPz4m8mAiCOj8YeIC4XvM
# tfw+NO6CvEU6pnUkmvIGLbF9TL1hAHEme199zAzBy4HJgpTnFw72LbAk9bi3KJ3u
# xTDwKWLdBB/+j83fY1vOef3HQ0imzAnJ32dyoc2EMcAC8n5lKaxP6W3mPQyxZNBl
# mmHFhCLp+PttISmJGmNkXqhB6wt1uCdy36+Y9QftvSoJKULgieB5QPUtnYj6
# SIG # End signature block
