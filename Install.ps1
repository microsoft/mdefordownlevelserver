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
    .\Install.ps1 -UI -Log -Etl
.EXAMPLE
    .\Install.ps1 -Uninstall
.EXAMPLE
    .\Install.ps1 -Uninstall -Etl
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
    ## Enables MSI logging to troubleshoot MSI install/uninstall failures.
    [switch] $Log,
    [Parameter(ParameterSetName = 'install')]
    [Parameter(ParameterSetName = 'uninstall')]
    ## Enables ETW logging.
    [switch] $Etl)

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

$osVersion = Get-OSVersion

[string] $msi = if ((-not $DevMode.IsPresent) -and (Test-Path -Path "$PSScriptRoot\md4ws.msi")) {
    Join-Path -Path:$PSScriptRoot "md4ws.msi"
} else {
    $Etl = $true
    $Log = $true
    Join-Path -Path:$PSScriptRoot "md4ws-devmode.msi"
}

$action = if ($Uninstall.IsPresent) { 'uninstall' }  else { 'install' }

$logBase = "$action-$env:COMPUTERNAME-$osVersion"

if ($Etl.IsPresent) {
    $Log = $true
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

    [bool] $needAdministrator = $false    
    if ($OnboardingScript.Length) {
        if (-not (Test-Path -Path:$OnboardingScript -PathType:Leaf)) {
            Write-Error "$OnboardingScript does not exist" -ErrorAction:Stop
        }
        $needAdministrator = $true
    }

    if ($OffboardingScript.Length) {
        if (-not (Test-Path -Path:$OffboardingScript -PathType:Leaf)) {
            Write-Error "$OffboardingScript does not exist" -ErrorAction:Stop
        }
        $needAdministrator = $true
    }
    
    if ($needAdministrator -and -not (Test-IsAdministrator)) {
        Write-Error "Onboarding/Offboarding scripts need to be invoked from an elevated process." -ErrorAction:Stop
    }
    
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
    if ($log.IsPresent -and (Test-Path -Path:$msiLog -PathType:Leaf)) {
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
            # Server 2016 - Windows Defender is shipped with OS, need to check if inbox version is updatable and latest.
            # Expectations are that 'Windows Defender Features' are installed and up-to-date
            if ((Get-Service -Name:'WinDefend').Status -eq 'Running') {
                $imageName = (Get-ItemPropertyValue -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
                $currentVersion = Get-FileVersion -File:$imageName
                if ($currentVersion -lt '4.10.14393.2515') {
                    Write-Error 'Windows Defender platform update requirement not met. Please apply the latest cumulative update (LCU) for Windows first. Minimum required is https://support.microsoft.com/en-us/help/4457127' -ErrorAction:Stop
                }
                $previousProgressPreference = $Global:ProgressPreference
                try {
                    $Global:ProgressPreference = 'SilentlyContinue'
                    $uri = 'https://go.microsoft.com/fwlink/?linkid=870379&arch=x64'
                    $latestVersion = ([xml]((Invoke-WebRequest -UseBasicParsing -Uri:"$uri&action=info").Content)).versions.platform
                    if ($currentVersion -lt $latestVersion) {
                        $tmpDir = Join-Path -Path:$env:TEMP ([guid]::NewGuid())
                        $null = New-Item -Path:$tmpDir -ItemType:Directory
                        $updatePlatform = Join-Path -Path:$tmpDir "UpdatePlatform.exe"
                        Write-Host "Downloading latest UpdatePlatform.exe (version $latestVersion) from $uri"
                        Invoke-WebRequest -UseBasicParsing -Uri:$uri -OutFile:$updatePlatform
                        $status = (Get-AuthenticodeSignature -FilePath:$updatePlatform).Status
                        if ($status -ne 'Valid') {
                            Write-Error "Unexpected authenticode signature status($status) for $updatePlatform" -ErrorAction:Stop
                        }
                        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($updatePlatform)
                        if ('UpdatePlatform.exe' -ne $fileInfo.InternalName -or 'Microsoft Malware Protection' -ne $fileInfo.ProductName) {
                            Write-Error "Unexpected file: $updatePlatform, InternalName='$($fileInfo.InternalName)', ProductName='$($fileInfo.ProductName)'" -ErrorAction:Stop
                        }
                        Write-Host ("Running UpdatePlatform.exe (version {0})" -f (Get-FileVersion -File:$updatePlatform))
                        $proc = Start-Process -FilePath:$updatePlatform -Wait -PassThru
                        if ($proc.ExitCode -ne 0) {
                            Write-Error "$updatePlatform failed with exitCode=$($proc.ExitCode)" -ErrorAction:Stop
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
                Write-Error "'WinDefend' service is not running. Please install 'Windows Defender Features'" -ErrorAction:Stop
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

    if ($Log.IsPresent) {
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
    if ($Etl.IsPresent) {
        Invoke-Command @etlparams -ScriptBlock: {
            param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
            & logman.exe stop -n $logBase -ets *>$null
            Write-Host "Tracing session '$logBase' stopped."
            Remove-ItemProperty -Path:$reportingPath -Name:$wppTracingLevel -ErrorAction:SilentlyContinue
        }
        Move-Item -Path:$tempFile -Destination:$etlLog -ErrorAction:Continue
        Write-Host "ETL file: '$etlLog'."
    }   

    if ($Log.IsPresent -and (Test-Path -Path:$tempMsiLog -PathType:Leaf)) {
        Move-Item -Path:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Write-Host "Msi log: '$msiLog'"
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.
# SIG # Begin signature block
# MIIliAYJKoZIhvcNAQcCoIIleTCCJXUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNcbXufj7nbFOf
# aEpmqWMz8FxC3LRP/x935CqCMxyxhKCCC2IwggTvMIID16ADAgECAhMzAAAJAItk
# /oXu0tXAAAAAAAkAMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIxMDkwOTE5MDUxN1oXDTIyMDkwMTE5MDUxN1owcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4WpJLjIYI
# AjC4/noZ8FS/krfY5902C0g2y4XikDsZcxwBKjY0wVkKas04MJzNWSgCBw/5l5hX
# 7udsJ9LogqS2pN5sq6O0YqYs9NOEmk6rsr5wRWmfN/LQRhEfsqfjwFt+d+QB5Z3/
# 19m41c+ADqaNcxHuLolO/z67Kp9rKb2QueoTqvAtRgW1+TUT7OGzMODncaUFz7+u
# vKGHuQ1fj1/9qsUC2udPkvI1A8eHbej+Dzkk9thnAv+f4L7nEQtDQ8YlE12yrg/i
# hk5e4Q6Mw/gHblQy2J/8ANdTqxLvm3ZzU844NxZZbt6kMhnzMeHUsYBwFkhlaMuq
# hYf/vzTIuw0BAgMBAAGjggF3MIIBczAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQU5us9cgqV4DadUnqIG+zNE+AN13MwVAYDVR0RBE0w
# S6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEWMBQGA1UEBRMNMjMwMDI4KzQ2NzYwMTAfBgNVHSMEGDAWgBTRT6mKBwjO
# 9CQYmOUA//PWeR03vDBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5j
# cmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBapqjIcyI2KnzXdBcyZW8g8jA/
# /hFs3KyGx2sQ7eDBy0v4Q0VKWRtfCtWeKHR11elksc/s8MO4cCQH50KG/JOyj7Yf
# YGvIAIpYOrxDjtzvOFTbXvZ13NFB3rwhm30t9ON/7At/5IZlHV7RUGb6tePn4Eom
# DtijTk7ekzyi9hTWPpSl+yB0L/gKN9TAVJiXCvCHzv9pBXScyxKtZKAnmrt4C8Gs
# cyMo6kcmFeG4eYxdtjc/ChKdipVN6NMJMJ5GVqoYMfJdZwpbAdukrQmlINTElGhE
# Lf+4hKtPEnz5jmjG0Bcx9gBrJ9drhnvUmb2crU3dO69OxKgQ75wmcpPxJDq3MIIG
# azCCBFOgAwIBAgIKYQxqGQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIz
# WhcNMjUwNzA2MjA1MDIzWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+
# DZ0U5LGfwciUsDh8H9AzVfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdS
# cFosHZSrGb+vlX2vZqFvm2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/
# OEbmisdzaXZVaZZM5NjwNOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMU
# pUwIoIPXIx/zX99vLM/aFtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jA
# vguTHijgc23SVOkoTL9rXZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEA
# AaOCAeMwggHfMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQY
# mOUA//PWeR03vDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0g
# BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUH
# AgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBl
# AG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnC
# lHDDZJTD2FamkI7+5Jr0bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz
# /Q2QJCTj+dyWyvy4rL/0wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0b
# jPMAYkG6SHSHgv1QyfSHKcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9
# TUj3bkFHUhy7G8JXOqiZVpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b
# 3CLVFCNqQX/QQqbb7yV7BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9
# pE/oGw5rduS4j7DC6v119yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6Mj
# ugagwI7RiE+TIPJwX9hrcqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpol
# Vf1Ayq1kEOgx+RJUeRryDtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ
# 239Q+J9iguymghZ8ZrzsmbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcN
# Gw186/RayZXPhxIKXezFApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w
# 3gI/h+5WoezrtUyFMYIZfDCCGXgCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENB
# IDIwMTACEzMAAAkAi2T+he7S1cAAAAAACQAwDQYJYIZIAWUDBAIBBQCgga4wGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIDdHawnq20Rh9oEQM8/oJYTWYpLM0W2SB0/H
# Mq3s9KT9MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEa
# gBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAO6kK
# HePfreijApI3sOItL9Meg8XjkqULfXMpHFYb8XNxKPk/0320ps+8Rd4voMi1SLxG
# n2e+9YgGJHAyfBK+lecmLRHOv3wNBQcTdsq8TCvEMjfZZoUeZTbjqM7WpKeilCHO
# ZQF/r/SXrRmZSiYeJ0JDW8oW08f8WedKr8o/4GPy8Abi+ub3awJfJqM4SLPgnLOU
# SmGuxiBvrcxKeMa9nKBDES1I5xHQV1qxIRCsbfuNJj8YWENUwnDs04vxVsknxcSm
# PfueLCiFitUqEgSMGVU4DvusibqW5V0zadI6eDFsatfbvwZuM/gHx8Imz9yipX72
# lQQ6iHCwyHH2euW/baGCFwswghcHBgorBgEEAYI3AwMBMYIW9zCCFvMGCSqGSIb3
# DQEHAqCCFuQwghbgAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFUBgsqhkiG9w0BCRAB
# BKCCAUMEggE/MIIBOwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDB
# 1ckpKS7goayNqTgL5REhUh/it1tFx3bFnm8SHApbAAIGYjAs/A3zGBIyMDIyMDQx
# MjEwMjcyNS41N1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEV8wggcQ
# MIIE+KADAgECAhMzAAABo/uas457hkNPAAEAAAGjMA0GCSqGSIb3DQEBCwUAMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMwMjE4NTExNloXDTIz
# MDUxMTE4NTExNlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAO+9TcrLeyoKcCqLbNtz7Nt2JbP1TEzzMhi84gS6YLI7CF6d
# VSA5I1bFCHcw6ZF2eF8Qiaf0o2XSXf/jp5sgmUYtMbGi4neAtWSNK5yht4iyQhBx
# n0TIQqF+NisiBxW+ehMYWEbFI+7cSdX/dWw+/Y8/Mu9uq3XCK5P2G+ZibVwOVH95
# +IiTGnmocxWgds0qlBpa1rYg3bl8XVe5L2qTUmJBvnQpx2bUru70lt2/HoU5bBbL
# KAhCPpxy4nmsrdOR3Gv4UbfAmtpQntP758NRPhg1bACH06FlvbIyP8/uRs3x2323
# daaGpJQYQoZpABg62rFDTJ4+e06tt+xbfvp8M9lo8a1agfxZQ1pIT1VnJdaO98gW
# MiMW65deFUiUR+WngQVfv2gLsv6o7+Ocpzy6RHZIm6WEGZ9LBt571NfCsx5z0Ilv
# r6SzN0QbaWJTLIWbXwbUVKYebrXEVFMyhuVGQHesZB+VwV386hYonMxs0jvM8GpO
# cx0xLyym42XA99VSpsuivTJg4o8a1ACJbTBVFoEA3VrFSYzOdQ6vzXxrxw6i/T13
# 8m+XF+yKtAEnhp+UeAMhlw7jP99EAlgGUl0KkcBjTYTz+jEyPgKadrU1of5oFi/q
# 9YDlrVv9H4JsVe8GHMOkPTNoB4028j88OEe426BsfcXLki0phPp7irW0AbRdAgMB
# AAGjggE2MIIBMjAdBgNVHQ4EFgQUUFH7szwmCLHPTS9Bo2irLnJji6owHwYDVR0j
# BBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGlt
# ZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggr
# BgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9N
# aWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0T
# AQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEA
# WvLep2mXw6iuBxGu0PsstmXI5gLmgPkTKQnjgZlsoeipsta9oku0MTVxlHVdcdBb
# FcVHMLRRkUFIkfKnaclyl5eyj03weD6b/pUfFyDZB8AZpGUXhTYLNR8PepM6yD6g
# +0E1nH0MhOGoE6XFufkbn6eIdNTGuWwBeEr2DNiGhDGlwaUH5ELz3htuyMyWKAgY
# F28C4iyyhYdvlG9VN6JnC4mc/EIt50BCHp8ZQAk7HC3ROltg1gu5NjGaSVdisai5
# OJWf6e5sYQdDBNYKXJdiHei1N7K+L5s1vV+C6d3TsF9+ANpioBDAOGnFSYt4P+ut
# W11i37iLLLb926pCL4Ly++GU0wlzYfn7n22RyQmvD11oyiZHhmRssDBqsA+nvCVt
# fnH183Df5oBBVskzZcJTUjCxaagDK7AqB6QA3H7l/2SFeeqfX/Dtdle4B+vPV4lq
# 1CCs0A1LB9lmzS0vxoRDusY80DQi10K3SfZK1hyyaj9a8pbZG0BsBp2Nwc4xtODE
# eBTWoAzF9ko4V6d09uFFpJrLoV+e8cJU/hT3+SlW7dnr5dtYvziHTpZuuRv4KU6F
# 3OQzNpHf7cBLpWKRXRjGYdVnAGb8NzW6wWTjZjMCNdCFG7pkKLMOGdqPDFdfk+EY
# E5RSG9yxS76cPfXqRKVtJZScIF64ejnXbFIs5bh8KwEwggdxMIIFWaADAgECAhMz
# AAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0z
# MDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP9
# 7pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMM
# tY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gm
# U3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130
# /o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP
# 3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7
# vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+A
# utuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz
# 1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6
# EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/Zc
# UlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZy
# acaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJ
# KwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVd
# AF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8G
# CCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3Mv
# UmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQC
# BAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYD
# VR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
# dXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cB
# MSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7
# bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/
# SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2
# EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2Fz
# Lixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0
# /fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9
# swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJ
# Xk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+
# pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW
# 4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N
# 7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyhgdSkgdEwgc4xCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jv
# c29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAHl/pXkLMAbPapCwa+GXc3SlDDROg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOX/lLwwIhgPMjAyMjA0MTIxMDAzNDBaGA8yMDIyMDQxMzEwMDM0MFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5f+UvAIBADAKAgEAAgIiuQIB/zAHAgEA
# AgJNvzAKAgUA5gDmPAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAH+ISSi4
# k16JLxinvPURCm92zdHINP/ypyl3q7UWz/hPIUtQrmY1PfGMcmTGEtuj99w7NeVg
# gazcuY0sl8sUb4QONvCBfiS6bKSc25YBHkD73CLLoLQm3pYiVfWNtOEpy4bye0Oz
# 0neTgFuwATlEw4qSQcW0cxckcFFH+0zP04i3MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGj+5qzjnuGQ08AAQAAAaMwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgmqdCPz7U+MzbBDwrKoL0eEQP1rQbhYp43dj7r3dFQPkwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCM+LiwBnHMMoOd/sgbaYxpwvEJlREZ
# l/pTPklz6euN/jCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABo/uas457hkNPAAEAAAGjMCIEIER0NHfSbOCQ6WW3zfUYYKeRaP3jTqWj
# 7NH01hf6BX7jMA0GCSqGSIb3DQEBCwUABIICALtOxpwFn5S4rShdRa7S/MvZeKJC
# eKOAfW7aEdj6jRApKGmejmtBGkkkXnbqU9CyaswRx9jJzz/342MKSNfddQct+U22
# 3J9PpWQphDQzpbMzHeyXmuRfrM54Z52/NFK+u+qi5T4/dYrZz25uVa86m11ndm3y
# Mdn9N94Nd9p+n49s2e4aXLqwdJrKJ1vV8MAlu2KE5uHobJ4l9J/SiHm9agYNu9j2
# 2U+DYlYw9fuWRPagABVO/8KiqsYxwQK3p13ixT9ReHzQkpIr1FnLdrWvaR8LlDPo
# sQOwULkHeu/LEAD/y/G139Dh7iKnN9tqN5Zbk01/8nJ1MolTmsR4gxzt7EihsX8j
# WoOB4PdyZDRVOuIZwp56496S1GxWpnjMZIn9gj+gnse0MJlp7g9HlH9L3/s+Ceeq
# hFQyv1g6T5IkQx2CVnvX6VuRMhhpBtloONJS+SOLqolJcKQRczqrOrzM1szwX5mm
# QcvAuhrIMBlAJZ3w+61bilefjsuv15hPd0KY+tuVhBS+vPSf2EiFWKM6IIKuZGll
# lePF3xhMS6xNM2qgGMpSkl/FRW2Hq617pK1SvOE2RmbJ+SHvVrVplTadRrS1ZGaf
# +u8FPgKpEuEpPojjqP7tTTLplCoOFba0ux0egnqgo9EhZmxTkDCCdK4F275ovVIH
# DQDmmNUG2Ounj33c
# SIG # End signature block
