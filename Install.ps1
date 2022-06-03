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
        It will run the offboarding script, if provided. Otherwise it is assumed that WD-ATP is offboarded.
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
    [bool] $needAdministrator = $false    
    if ($OnboardingScript.Length) {
        if (-not (Test-Path -Path:$OnboardingScript -PathType:Leaf)) {
            Write-Error "$OnboardingScript does not exist" -ErrorAction:Stop
        }
        
        ## validate it is an "onboarding" script.
        $on = Get-Content -Path:$OnboardingScript | Where-Object {
            $_ -match 'reg\s+add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+OnboardingInfo'
        }
        if ($on.Length -eq 0) {
            Write-Error "Not an onboarding script: $OnboardingScript" -ErrorAction:Stop
        }

        $needAdministrator = $true
    }

    if ($OffboardingScript.Length) {
        if (-not (Test-Path -Path:$OffboardingScript -PathType:Leaf)) {
            Write-Error "$OffboardingScript does not exist" -ErrorAction:Stop
        }

        $off = Get-Content -Path:$OffboardingScript | Where-Object {
            $_ -match 'reg\s+add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A'
        }
        
        if ($off.Length -eq 0) {
            Write-Error "Not an offboarding script: $OffboardingScript" -ErrorAction:Stop
        }
        $needAdministrator = $true
    }
    
    if ($needAdministrator -and -not (Test-IsAdministrator)) {
        Write-Error "Onboarding/Offboarding scripts need to be invoked from an elevated process." -ErrorAction:Stop
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
        [AllowEmptyString()] [AllowEmptyCollection()] [string[]] $ArgumentList
    )

    $mpCmdRun = Join-Path -Path:$(Get-RegistryKey -Path:'HKLM:\SOFTWARE\Microsoft\Windows Defender' -Name:'InstallLocation') 'MpCmdRun.exe'

    $startParams = @{
        FilePath    = $mpCmdRun
        Wait        = $true
        NoNewWindow = $true
        PassThru    = $true        
    }
    
    if ($ArgumentList) {
        $startParams.ArgumentList = $ArgumentList
    }

    try {
        Write-Host "Invoking `"$(Split-Path $startParams.FilePath -Leaf) $ArgumentList`""
        $proc = Start-Process @startParams
        if ($null -ne $proc -and $proc.ExitCode -ne 0) {
            Write-Error ("Command `"$(Split-Path $startParams.FilePath -Leaf) $ArgumentList`" failed with error 0x{0:x}" -f $proc.ExitCode) -ErrorAction:Stop
        }
    } catch {
        throw
    } finally {
        if ($null -ne $proc) {
            $proc.Dispose()
        }
    }
}

Test-ExternalScripts
if ('Tls12' -notin [Net.ServicePointManager]::SecurityProtocol) {
    ## Server 2016/2012R2 might not have this one enabled and all Invoke-WebRequest might fail.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Host "[Net.ServicePointManager]::SecurityProtocol updated to '$([Net.ServicePointManager]::SecurityProtocol)'"
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
    Write-Error "Cannot create $tempFile. Is $PSScriptRoot writable?" -ErrorAction:Stop
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
            Write-Host "Tracing session '$logBase' started."
        } catch {
            throw
        } finally {
            Remove-Item -Path:$wdprov -ErrorAction:Continue
        }
    }
}

try {
    $tempMsiLog = Join-Path -Path:$env:TEMP "$([guid]::NewGuid().Guid).log"

    if ($null -ne $RemoveMMA) {
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
        $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
        if ($RemoveMMA -in $workspaces) {
            Write-Host "Removing cloud workspace $($RemoveMMA.Guid)..." 
            $mma.RemoveCloudWorkspace($RemoveMMA)
            $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
            if ($workspaces.Count -gt 0) {
                $mma.ReloadConfiguration()
            } else {
                Stop-Service HealthService
            }
            Write-Host "Workspace $($RemoveMMA.Guid) removed."
        } else {
            Write-Error "Invalid workspace id $($RemoveMMA.Guid)" -ErrorAction:Stop
        }
    }
    
    $msiLog = "$PSScriptRoot\$logBase.log"    
    if ($log -and (Test-Path -Path:$msiLog -PathType:Leaf)) {
        if (Test-Path -Path:"$PSScriptRoot\$logBase.prev.log") {
            Remove-Item -Path:"$PSScriptRoot\$logBase.prev.log" -ErrorAction:Stop
        }
        Rename-Item -Path:$msiLog -NewName:"$PSScriptRoot\$logBase.prev.log"
    }

    $command = @{
        WorkingDirectory = $PSSCriptRoot
        Wait             = $true
        NoNewWindow      = $true
        PassThru         = $true
    }
            
    if ($action -eq 'install') {
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            $windefend = Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue
            $wdnissvc = Get-Service -Name:'WdNisSvc' -ErrorAction:SilentlyContinue
            $wdfilter = Get-Service -Name:'WdFilter' -ErrorAction:SilentlyContinue
            if ($windefend -and -not $wdnissvc -and -not $wdfilter) {
                ## workaround for ICM#278342470. Fixed on MOCAMP version 4.18.2111.150 or newer.
                if ($windefend.Status -eq 'Running') {
                    Write-Error "Please reboot this computer to remove 'WinDefend' Service" -ErrorAction:Stop
                } elseif ($windefend.Status -eq 'Stopped') {
                    Remove-Item -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Force -Recurse -ErrorAction:Stop
                    Write-Error "Please restart this machine to complete 'WinDefend' service removal" -ErrorAction:Stop
                } else {
                    Write-Error "Unexpected state: $($windefend.Status)" -ErrorAction:Stop
                }
            }

            ## SCEP is different on Server 2016.
            $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Security Client"        
            if (Test-Path -Path:$path) {
                $displayName = (Get-ItemProperty -Path:$path -Name:'DisplayName').DisplayName
                $command.FilePath = "$env:ProgramFiles\Microsoft Security Client\Setup.exe"
                # See camp\src\amcore\Antimalware\Source\AppLayer\Components\Distribution\Common\CmdLineParser.h
                $command.ArgumentList = @('/u', '/s');
                $proc = Start-Process @command
                if ($proc.ExitCode -eq 0) {
                    Write-Host "Uninstalling '$displayName' successful."
                } else {
                    Write-Warning "Uninstalling '$displayName' exitcode: $($proc.ExitCode)."
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
                        Write-Host "$KB already installed."
                        return
                    }
                    Write-Host "Downloading $KB to $outFile"
                    Invoke-WebRequest -Uri:$Uri -OutFile:$outFile -ErrorAction:Stop
                    $command.FilePath = (Get-Command 'wusa.exe').Path
                    $command.ArgumentList = @($outFile, '/quiet', '/norestart')
                    Write-Host "Installing $KB"
                    $proc = Start-Process @command
                    if ($proc.ExitCode -eq 0) {
                        Write-Host "$KB installed."
                    } elseif ($proc.ExitCode -eq 0x80240017) {
                        #0x80240017 = WU_E_NOT_APPLICABLE = Operation was not performed because there are no applicable updates.
                        Write-Warning "$KB not applicable, continuing..."
                    } else {
                        Write-Warning "$KB installation failed with exitcode: $($proc.ExitCode)."
                    }
                } catch {
                    ## Might be OK to continue (MSI installer will recheck these dependencies and it will fail.)
                    Write-Warning "ignoring error/exception: $_"
                    #throw
                } finally {
                    $ProgressPreference = $PreviousProgressPreference
                    if (Test-Path -Path:$outFile -PathType:Leaf) {
                        Write-Host "Removing $outFile"
                        Remove-Item -Path:$outFile -Force -ErrorAction:SilentlyContinue
                    }
                }
            }
            ## ucrt dependency (needed by WinDefend service)
            Install-KB -Uri:'https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu' -KB:KB2999226 -ScriptBlock: {
                Test-Path -Path:$env:SystemRoot\system32\ucrtbase.dll -PathType:Leaf
            }
            ## telemetry dependency (needed by Sense service)
            Install-KB -Uri:'https://download.microsoft.com/download/4/E/8/4E864B31-7756-4639-8716-0379F6435016/Windows6.1-KB3080149-x64.msu' -KB:KB3080149 -ScriptBlock: {
                if (Test-Path -Path:$env:SystemRoot\system32\Tdh.dll -PathType:Leaf) {
                    $verInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:SystemRoot\system32\Tdh.dll")
                    $fileVersion = New-Object -TypeName:System.Version -ArgumentList:$verInfo.FileMajorPart, $verInfo.FileMinorPart, $verInfo.FileBuildPart, $verInfo.FilePrivatePart
                    $minFileVersion = New-Object -TypeName:System.Version -ArgumentList:6, 3, 9600, 17958
                    return $fileVersion -ge $minFileVersion
                }
                return $false
            }
        } elseif ($osVersion.Major -eq 10 -and $osVersion.Minor -eq 0 -and $osVersion.Build -lt 18362) {
            $defenderFeature = Get-WindowsOptionalFeature -Online -FeatureName:'Windows-Defender-Features' -ErrorAction:Stop
            if ($defenderFeature.State -ne 'Enabled') {
                $defenderFeature = $defenderFeature | Enable-WindowsOptionalFeature -Online -NoRestart
            }
            if ($defenderFeature.RestartNeeded) {
                Write-Error "Restart is required by 'Windows-Defender-Features'" -ErrorAction:Stop
            }

            $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            if ($windefendStatus -ne 'Running') {
                ## try to start it using 'mpcmdrun wdenable' (best effort)
                $disableAntiSpyware = Get-RegistryKey -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'DisableAntiSpyware'
                if ($null -ne $disableAntiSpyware -and 0 -ne $disableAntiSpyware) {
                    Write-Warning "DisableAntiSpyware is set to $disableAntiSpyware (should be zero)"
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
                    Write-Error 'Windows Defender platform update requirement not met. Please apply the latest cumulative update (LCU) for Windows first. Minimum required is https://support.microsoft.com/en-us/help/4457127' -ErrorAction:Stop
                }
                $previousProgressPreference = $Global:ProgressPreference
                try {
                    $Global:ProgressPreference = 'SilentlyContinue'
                    $msiVersion = (Get-MsiFilesInfo -MsiPath:$msi).'MPCLIENT.DLL'.Version
                    $updatePlatformBaseName = if ($DevMode.IsPresent) { 'UpdatePlatformD.exe' } else { 'UpdatePlatform.exe' }
                    if ($currentVersion -lt $msiVersion) {
                        Write-Host "Current platform version is $currentVersion, msiVersion is $msiVersion"
                        $updatePlatform = Join-Path -Path:$PSScriptRoot $updatePlatformBaseName
                        if (-not (Test-Path -Path:$updatePlatform -PathType:Leaf) -and -not $DevMode.IsPresent) {
                            ## Download $updatePlatformBaseName from $uri *only if* the UpdatePlatform is not present.
                            $uri = 'https://go.microsoft.com/fwlink/?linkid=870379&arch=x64'
                            Write-Host "$updatePlatformBaseName not present under $PSScriptRoot"
                            $latestVersion = ([xml]((Invoke-WebRequest -UseBasicParsing -Uri:"$uri&action=info").Content)).versions.platform
                            if ($latestVersion -lt $msiVersion) {
                                Write-Warning "Changing $msiVersion from $msiVersion to $latestVersion"
                                $msiVersion = $latestVersion
                            }
                            Write-Host "Downloading latest $updatePlatformBaseName (version $latestVersion) from $uri"
                            Invoke-WebRequest -UseBasicParsing -Uri:$uri -OutFile:$updatePlatform
                        }
                        $updatePlatformVersion = Get-FileVersion -File:$updatePlatform
                        if ($updatePlatformVersion -lt $msiVersion) {
                            Write-Error "Minimum required version is $msiVersion. $updatePlatform version is $updatePlatformVersion" -ErrorAction:Stop
                        }

                        $status = (Get-AuthenticodeSignature -FilePath:$updatePlatform).Status
                        if ($status -ne 'Valid') {
                            Write-Error "Unexpected authenticode signature status($status) for $updatePlatform" -ErrorAction:Stop
                        }
                        ## make sure the right file was downloaded (or present in this directory)
                        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($updatePlatform)
                        if ($updatePlatformBaseName -ne $fileInfo.InternalName) {
                            Write-Error "Unexpected file: $updatePlatform, InternalName='$($fileInfo.InternalName)' (expecting '$updatePlatformBaseName')" -ErrorAction:Stop    
                        }                       
                        if ('Microsoft Malware Protection' -ne $fileInfo.ProductName) {
                            Write-Error "Unexpected file: $updatePlatform, ProductName='$($fileInfo.ProductName)' (expecting 'Microsoft Malware Protection')" -ErrorAction:Stop    
                        }

                        Write-Host ("Running $updatePlatformBaseName (version {0})" -f (Get-FileVersion -File:$updatePlatform))
                        $proc = Start-Process -FilePath:$updatePlatform -Wait -PassThru
                        if ($proc.ExitCode -ne 0) {
                            Write-Error ("$updatePlatform failed with exitCode=0X{0:X}" -f $proc.ExitCode) -ErrorAction:Stop
                        }
                        $imageName = (Get-ItemPropertyValue -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
                        $currentVersion = Get-FileVersion -File:$imageName
                        if ($currentVersion -lt $latestVersion) {
                            Write-Error "Current version is $currentVersion, expected to be at least $latestVersion" -ErrorAction:Stop
                        }
                        Write-Host "Current platform version is $currentVersion"
                    }
                } catch {
                    throw
                } finally {
                    if ($null -ne $tmpDir -and (Test-Path -Path:$tmpDir -PathType:Container)) {
                        Remove-Item -Path:$tmpDir -Force -Recurse -ErrorAction:SilentlyContinue
                        if (Test-Path -Path:$tmpDir -PathType:Container) {
                            Write-Warning "Could not remove $tmpDir, ignoring it."
                        }
                    }
                    $Global:ProgressPreference = $previousProgressPreference
                }
            } else {
                Write-Error "'WinDefend' service is not running." -ErrorAction:Stop
            }
        } else {
            Write-Error "Unsupported OS version: $osVersion" -ErrorAction:Stop
        }
    }

    ## The new name is 'Microsoft Defender for Endpoint' - to avoid confusions on Server 2016.
    $displayName = 'Microsoft Defender for (Windows Server|Endpoint)'
    $uninstallGUID = Get-UninstallGuid -DisplayName:$displayName

    if ($OffboardingScript.Length -gt 0 -and ($action -eq 'uninstall' -or $null -ne $uninstallGUID)) {
        Write-Host "Invoking offboarding script $OffboardingScript"
        $command.FilePath = (Get-Command 'cmd.exe').Path
        $scriptPath = if ($OffboardingScript.Contains(' ') -and -not $OffboardingScript.StartsWith('"')) {
            '"{0}"' -f $OffboardingScript
        } else {
            $OffboardingScript
        }
        $command.ArgumentList = @('/c', $scriptPath)
        $proc = Start-Process @command
        if ($proc.ExitCode -eq 0) {
            Write-Host "Offboarding successful."
        } else {
            Write-Error "Offboarding script returned $($proc.ExitCode)." -ErrorAction:Stop
        }
        
        # SenseIR up to version 10.8045.22439.1011 leaks SenseIRTraceLogger ETW session, preventing a clean install/uninstall.
        # See VSO#36551957
        & logman.exe query "SenseIRTraceLogger" -ets *>$null
        if (0 -eq $LASTEXITCODE) {
            Write-Warning "SenseIRTraceLogger still present, removing it!"
            & logman.exe stop -n "SenseIRTraceLogger" -ets *>$null
            if (0 -ne $LASTEXITCODE) {
                Write-Warning "SenseIRTraceLogger could not be removed, exitCode=$LASTEXITCODE"
            }
        }
    }

    if ($action -eq 'uninstall') {
        foreach ($name in 'ConfigDefender', 'Defender') {
            $defender = Get-Module $name -ErrorAction:SilentlyContinue
            if ($defender) {
                Remove-Module $defender
                Write-Host 'Defender module unloaded.'
                break
            }
        }
    }

    $command.FilePath = (Get-Command 'msiexec.exe').Path   
    $command.ArgumentList = if ($action -eq 'install') {
        if (-not (Test-Path -Path:$msi -PathType:leaf)) {
            Write-Error "$msi does not exist." -ErrorAction:Stop
        }
        if ($msi.Contains(' ')) { @('/i', "`"$msi`"") } else { @('/i', $msi) }
    } else {
        if ($null -eq $uninstallGUID) {
            Write-Error "'$displayName' already uninstalled." -ErrorAction:Stop
        }
        @('/x', $uninstallGUID)
    }

    if ($log) {
        $command.ArgumentList += '/lvx*+'
        $command.ArgumentList += if ($tempMsiLog.Contains(' ')) { "`"$tempMsiLog`"" } else { $tempMsiLog }
    }

    if (-not $UI.IsPresent) {
        $command.ArgumentList += '/quiet'
    }

    if ($Passive.IsPresent) {
        Write-Host "Will force passive mode."
        $command.ArgumentList += 'FORCEPASSIVEMODE=1'
    }

    $proc = Start-Process @command
    if ($proc.ExitCode -eq 0) {
        Write-Host "$action successful."
    } else {
        Write-Error "$action exitcode: $($proc.ExitCode)." -ErrorAction:Stop
    }
    
    if ($action -eq 'install' -and $OnboardingScript.Length) {
        Write-Host "Invoking onboarding script $OnboardingScript"
        $command.FilePath = (Get-Command 'cmd.exe').Path
        $scriptPath = if ($OnboardingScript.Contains(' ') -and -not $OnboardingScript.StartsWith('"')) {
            '"{0}"' -f $OnboardingScript
        } else {
            $OnboardingScript
        }
        $command.ArgumentList = @('/c', $scriptPath)
        
        $proc = Start-Process @command
        if ($proc.ExitCode -eq 0) {
            Write-Host "Onboarding successful."
        } else {
            Write-Warning "Onboarding script returned $($proc.ExitCode)."
        }
    }
} catch {
    throw
} finally {
    if ($etl) {
        Invoke-Command @etlparams -ScriptBlock: {
            param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
            & logman.exe stop -n $logBase -ets *>$null
            Write-Host "Tracing session '$logBase' stopped."
            Remove-ItemProperty -Path:$reportingPath -Name:$wppTracingLevel -ErrorAction:SilentlyContinue
        }
        Move-Item -Path:$tempFile -Destination:$etlLog -ErrorAction:Continue
        Write-Host "ETL file: '$etlLog'."
    }   

    if ($log -and (Test-Path -Path:$tempMsiLog -PathType:Leaf)) {
        Move-Item -Path:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Write-Host "Msi log: '$msiLog'"
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.
# SIG # Begin signature block
# MIIleQYJKoZIhvcNAQcCoIIlajCCJWYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCf04artii0nw7B
# gEh+Za1TTTBNmvIMgXFwkFDL5b9lQ6CCC14wggTrMIID06ADAgECAhMzAAAI/yN0
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
# FTAvBgkqhkiG9w0BCQQxIgQgi8lKw3hKd9f4pkpuyNBhTvkhl0F83paYDvAqxP7/
# rS8wQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBT2gae3YDt
# 6XChV2y4Uf7pTtaFoq+iBe0LQ4A7n56RYg8bW9dM4tZKv5MuPBsFA+TXfHjR/HFo
# 3M95ps4wD5lYL0oRYzdERFMFshuSL5xKApE8uRs0njjskyIH3IRy7S9VxKzFrLOP
# 9QXAS+x3Vj8nP700fCjmTo78/fOVeMoGDyYqOz6sSi2c20Md8vGRYIS1spfpJ3qX
# cZlZQafh6SzdtCK8XpjB3Mqx6qAKgP3CEDtZQ3sd1YyCR2ZYy77Pp4QUCFUjaGoG
# NMr4o3/EouuSfa56PfpuIu86LmOT7GAWsRULql/2XH4oo1nN+gKOArStUtvBH1Bu
# sqLTzgtypi9ooYIXADCCFvwGCisGAQQBgjcDAwExghbsMIIW6AYJKoZIhvcNAQcC
# oIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIB
# QASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIBkgTIgG
# CcV96CwWk8w18nPMzT72y/J03wupdXOQpTgeAgZijoVnnwMYEzIwMjIwNjAzMTE0
# MDMxLjg0NlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNFNy0xNjg1MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0oAMC
# AQICEzMAAAGe/cIt2DFatrEAAQAAAZ4wDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkwNTIwWhcNMjMwMjI4MTkw
# NTIwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
# A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDu6VylSHXD8Da8XkVNIqDgwWpTrhL5XXBaw2Zzerm2srxV+NpL/Zv7pVASO/TD
# GhAEMcwZTxyajt8I4vZ4DnnF9TD4tP6EE5Qx1LQQoZAjq55UH9qqpc1nwRJNBlQi
# +WdAV7IiGjQBe8J+WYV3yvDqlEYFC5VMe8OsB7yOMpFrAIZq3DhPpTLJM1LRdNEV
# AtGFlLT5BbBw3FG6EgfQt6DifBYtsZquhPAaER9PIALFQxA138+ihNRZJMJUMhXY
# aAS6oLRN6pYZDDoXy4qqcGGeINsRBRZ91TN6lQgad8Cna+qH0tDQsQSJQfv74nJd
# gzkIpvz/DnvUFNZ9vqmh2OxNn82pX4nLuzAZCP4+zmFGYPAlo6ycnTc9Y8XNu8XV
# JYvno8uYYigRdRm2AYIfw04DYFhURE9hkckKIhxjqERNRxA0ZeHTUHA5t6ZS3xTO
# JOWgeB5W3PRhuAQyhITjGaUQUAgSyXzDzrOakNTVbjj7+X8OGsFtR8OYPzBe7l31
# SLvudNOq8Sxh2VA+WoGmdzhf+W7JmIEGAto//9u8HUtnoNzJK/dwS2MYucnimlOr
# xKVrnq9jv1hpgmHPobWHnnLhAgXnH4SjabyPkF1CZd8I2DLC56I4weWpcrtp+Tdh
# pvwBFvWi6onTs1uSFg4UBAotOVJjdXNK+01JVZF7nxs1cQIDAQABo4IBNjCCATIw
# HQYDVR0OBBYEFGjTPoPRdY6XPtQkSTroh9lkZbutMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAFS5VY6hmc8GH2D1
# 8v+STQA+A+gT1duE3yuNn1mH41TLquzVNLW03AzAvuucYea1VaitRE5UYbIzxUsV
# 9G8sTrXbdiczeVG66IpLullh4Ixqfn+xzGbPOZWUT6wAtgXq3FfMGY9k73qo/IQ5
# shoToeMhBmHLWeg53+tBcu8SzocSHJTieWcv5KmnAtoJra5SmDdZdFBCz0cP3IUq
# 4kedN0Q2KhKrMDRAeD/CCza2DX8Bj9tRePycTnvfsScCc5VsxDNCannq8tVJ+HQa
# zRVK8ANW2UMDgV63i7SKGb3+slKI/Y92ouMrTFhai6h4rCojzSsQtJQTCcnI0QTD
# oextzmaLsmtKu3jF2Ayh8gFed+KRDiDhtNcyZoJm+fmqaKhTIi9guPoed7wvn5zd
# e93Zr6RXBTtXL0dlR0FMw/wPQVJjLVEaEnYWnKZH9lU8XZJV+xOmWFBFZkd+RnVO
# W3ZW5eBGsLeuzDCAamruyotw4PD36T6eYGJv5YvrX1iRYADrxXCUYidrZJY2s0IV
# ZFicqGgp5FtYYnAMpE7tyuIj2o4y+ol1by3lQV6Ob0P4RnK6gnuECWBfmWSjevOf
# r+02mkseW8oREHAm9y9XfcdUcQ57vbbau8+AQia8wGQcNXpxAnoLDwJ+RAycDlpe
# 3e2Yha9nXuYzcVMk92r/bKI0fyGOMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
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
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpENkJELUUzRTct
# MTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUAAhXCOZBbDxA/B5Tei6Rf80L9GheggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOZEOHUwIhgP
# MjAyMjA2MDMxNTM2MjFaGA8yMDIyMDYwNDE1MzYyMVowdzA9BgorBgEEAYRZCgQB
# MS8wLTAKAgUA5kQ4dQIBADAKAgEAAgIBWAIB/zAHAgEAAgIRxTAKAgUA5kWJ9QIB
# ADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQow
# CAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJJ5SfNSqMGbfrNDxAuavLL8UG8X
# MD35jb2Tg+Xv+QZt0vfHcRm0/9pN/XsspmyiRwTlRTKkS4pTJ2CjtV6hTheIO9Hb
# VEm7fkBypZl0tuxc2sdSkE47su2zvoQXo2NjMQd0nS5A751E9ge1cO0lIyUo1/m4
# JnWFMZhO+p2ecbWyMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGe/cIt2DFatrEAAQAAAZ4wDQYJYIZIAWUDBAIBBQCgggFK
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgr/Ts
# SMqzxE9CzED/39ZsZkC4M6OU2AIfilMMIB7F6fAwgfoGCyqGSIb3DQEJEAIvMYHq
# MIHnMIHkMIG9BCAOxVYyIv5cj0+pZkJurJ+yCrq0Re5XgrkfStUO/W88GTCBmDCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABnv3CLdgxWrax
# AAEAAAGeMCIEIHzv+LiHpVTlj6GxvqZpAzsNRA9aQHNEulrlBShZ5P6zMA0GCSqG
# SIb3DQEBCwUABIICAGU5a8asXdJxNlSXK9hprwF11mgH+IyoogxmsOaJUr4v/6Vf
# cJZ+dEDiI+d8YPPd9fxQxpxCU5SQxdTWRqp/xMdYF9Itgr/TBb6j/pupIluV2iXy
# qZ2Jno12lq+C2Abz2j4SEdHlThPgf2RXpnPGAxq7wxFJF7QmVJy6LnXGhycSU6mu
# 3cVH+lcqW5SlWW94Cvj9t38w5DYi/fM3Z+JZYLNjH2ZoFn1Nk/xweG6J5gHgaJyn
# wCPjE3nBTdacmNS/lxdThzJEhHFIy4vnkKhyaiQL6rJ1FtWi7Kb9KeWwjwiErPON
# AeaRvJLjUj0S+ZQeNfdS8rqWcViDdGOun9V8XI6ztAxF5ArTuvVvAuyeDD9KHftc
# +YFdjEExyed28UHgr8UWQktz38CiXxZbjvRJ6j7wZVLACJBm4XAYxZW09nijfDPI
# pqZqqzWOLQuAAsEen1aFc3Rrh8Psi3IWZRpOnyjzVUUqLih7s4gYY20DB+0RfD10
# yri7s1sKc6m5F10ikSoNRElYLZ/oinaf1+ih+oxf+CG5wjs4xj0Yww4ZY1CvL+4P
# jnZh0o1oEInkqs99ldvKPHA3k9iUNdBfRszJA1DCGI/bJwwhRru7Wez7CVHwdvUp
# yA2HdBqTZmSoJRzCEq25glL8yVOwrNTNo/2bUcxo2Ia5pvL+6LL5h04TCG4D
# SIG # End signature block
