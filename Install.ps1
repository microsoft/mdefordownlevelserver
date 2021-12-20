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

$msi = if ((-not $DevMode.IsPresent) -and (Test-Path -Path $PSScriptRoot\md4ws.msi)) {
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

    $command.FilePath = (Get-Command 'msiexec.exe').Path   
    $command.ArgumentList = if ($action -eq 'install') {
        if (-not (Test-Path -Path:$msi -PathType:leaf)) {
            Write-Error "$msi does not exist." -ErrorAction:Stop
        }
        @('/i', """$msi""")
    } else {
        if ($null -eq $uninstallGUID) {
            Write-Error "'$displayName' already uninstalled." -ErrorAction:Stop
        }
        @('/x', $uninstallGUID)
    }

    if ($Log.IsPresent) {
        $command.ArgumentList += '/lvx*+', $tempMsiLog
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

    if ($action -eq 'uninstall') {
        $defender = Get-Module Defender
        if ($defender) {
            Remove-Module $defender
            Write-Host 'Defender module unloaded.'
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
# MIIhdwYJKoZIhvcNAQcCoIIhaDCCIWQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3so0D2vC1SJuK
# CD/C03P7Sy7p9jEhwVh6CPPHRrSd5aCCC14wggTrMIID06ADAgECAhMzAAAI/yN0
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
# 7lah7Ou1TIUxghVvMIIVawIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACP8jdOWzYgw+3gAAAAAI/zANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQg9PlyrEjDEuscbBwAsEZ9yd1ZYijwY8HrcV29DLi/
# uhgwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAwpnvJboRj
# Zqp4FVLGDRS5OT9oD+utOA6+9pfSxFL/3aDrurmBKnKNR/hjnuF3AoNJSZrSbuWn
# ewSP8DyYcyN3JwbOZYfpEuy6qSCK67CkAJyzDIuv0Hrj4QLnO/RqV+bb2ocxTt87
# WvXzfURS04syKK7MH4zQdDZKcV3eQ1pXPR2eyxjmjuPA4xWYgXuM799mpdMddpnx
# FS9adP5zeJaZhIBTtvpghfcYe/P9rFfi9BJm4yZSB6sUG3eCyRLdQSipBK1g/xTC
# vtPa3SarEeoIK6Sx1b/i06U/T3VKRyHIJfHhXVY45KIpxywOtDE4iTQ27nbqUDKL
# 4DTCFYx/HJ5RoYIS/jCCEvoGCisGAQQBgjcDAwExghLqMIIS5gYJKoZIhvcNAQcC
# oIIS1zCCEtMCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIExDbU1/
# Aifz+jFcbT2y0uqLsCzqyEJFA0Da5wz2diItAgZhlTNJeOcYEzIwMjExMTE5MDk1
# MjU2LjUzNVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQy
# MjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE
# +TCCA+GgAwIBAgITMwAAAUAjGdZe3pUkMQAAAAABQDANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMDEwMTUxNzI4MjZaFw0y
# MjAxMTIxNzI4MjZaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEArn1rM3Hq1S9N0z8R+YKqZu25ykk5OlT8TsuwtdBW
# yDCRFoASk9fB6siColFhXBhyej4c3yIwN0UyJWBOTAjHteOIYjfCpx539rbgBI5/
# BTHtC+qcBT7ftPknTtQn89lNOcpP70fuYVZLoQsDnLjGxxtW/eVewR5Q0I1mWQfJ
# y5xOfelk5OWjz3YV4HKtqyIRzJZd/RzcY8w6qmzoSNsYIdvliT2eeQZbyYTdJQsR
# ozIKTMLCJUBfVjow2fJMDtzDB9XEOdfhPWzvUOadYgqqh0lslAR7NV90FFmZgZWA
# RrG8j7ZnVnC5MOXOS/NI58S48ycsug0pN2NGLLk2YWjxCwIDAQABo4IBGzCCARcw
# HQYDVR0OBBYEFDVDHC4md0YgjozSqnVs+OeELQ5nMB8GA1UdIwQYMBaAFNVjOlyK
# MZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3
# LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEu
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggEBAGMMUq2gQuCC9wr4YhISfPyobaNYV3Ov4YwWsSfIz/j1xaN9TvLA
# B2BxPi2CtRbgbBUf48n07yReZInwu2r8vwLoNG2TtYzey01DRyjjsNoiHF9UuRLF
# yKZChkKC3o9r0Oy2x0YYjUpDxVChZ5q5cAfw884wP0iUcYnKKGn8eJ0nwpr7zr/T
# lu+HOjXDT9C754aS4KUFNm8D7iwuvWWzSOVl7XMWdu82BnnTmB7s2Ocf3I4adGzd
# ixQ5Zxxa3zOAvKzrV+0HcVQIY3SQJ9PzjDRlzCviMThxA8FUIRL3FnYqvchWkEoZ
# 4w8S7FsGWNlXLWQ7fHMb3l4gjueHyO4p6tUwggZxMIIEWaADAgECAgphCYEqAAAA
# AAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/F
# w+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC
# 3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd
# 0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHR
# D5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9E
# uqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsG
# AQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUA
# ZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
# hkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpX
# bRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvc
# XBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr
# 5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA
# 6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38
# ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooP
# iRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6ST
# OvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmy
# W9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3g
# hvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9
# zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKh
# ggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQy
# MjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAEKl5h7yE6Y7MpfmMpEbQzkJclFToIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlQavZMCIYDzIw
# MjExMTE5MTI1MTM3WhgPMjAyMTExMjAxMjUxMzdaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOVBq9kCAQAwCgIBAAICELsCAf8wBwIBAAICEUAwCgIFAOVC/VkCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBfEDu+kZyg13VfAGunBY6LO6K7/b3O
# cmrRxN+p9Theb63T7grJrZK+KxznY4nvxmLYgM5F3VUxeXRdJuwQZgYRv+voXsuD
# U/N26O195jiDifMoAjdN1LigdJm93/FRBrFpn6BMKqOQXUTUaaUxrh/0BBH2vZng
# sQoMeakAfoyAcjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABQCMZ1l7elSQxAAAAAAFAMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJ+p39v9
# 1r5XSBBOpHvtGr8OsU/Q60vUPBytBKwIZrFVMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgLzawterM0qRcJO/zcvJT7do/ycp8RZsRSTqqtgIIl4MwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAUAjGdZe3pUkMQAA
# AAABQDAiBCC9zexJj8e7h1Fxxe4lyJ97lPD9L8LQWoAD7Dzsk7RsIjANBgkqhkiG
# 9w0BAQsFAASCAQCtqV6J9hmW06HrWfApHmMHLpaV+YAigEHgBc8rpxBjfg6B5zl+
# eIOgNG7r5fk0JytgVpeLSQpb+g2evVT8iTjX3inUA49/KGPjC4eb5cplKYAZisut
# suirKb535R+dodK/TQ/mXf0ZenMkxhtm2a+bk5XSsGmVA8z1w+3K5hPpi1RS6IMi
# TSGsELupR7v9E6NvwnJ8jMXvyvTUsGrg5ZX1AQW2PcEVkjVaH9rXyLgk2KutHLYS
# p06zFgtngDSGNnVFNn/cIL9WlVH+VG2DLGvBsnJdEQr2VovIpHlurt+CHmOAYRbB
# oguRL8vR7N7QLaEfZIFttX/AcqA2yqIPMQL5
# SIG # End signature block
