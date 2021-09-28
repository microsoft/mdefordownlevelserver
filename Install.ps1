<#
.SYNOPSIS
    Helper script for installing/uninstalling Microsoft Defender for Downlevel Servers.
.DESCRIPTION
    On install scenario:
        It first removes MMA workspace when RemoveMMA guid is provided.
        Next uninstalls SCEP if present.
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
    ## Offboarding script to run prior to uninstalling MSI
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

$osVersion = [environment]::OSVersion.Version.ToString()

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
            @{Guid = 'B0CA1D82-539D-4FB0-944B-1620C6E86231'; Flags = 0xffffffff; Level = 0xff; Name = 'EventLog'},
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
    }

    [version] $osVersion = [System.Environment]::OSVersion.Version
    if ($action -eq 'install' -and $osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
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
                $minFileVersion = New-Object -TypeName:System.Version -ArgumentList:6,3,9600,17958
                return $fileVersion -ge $minFileVersion
            }
            return $false
        }
    }

    if ($action -eq 'uninstall' -and $OffboardingScript.Length -gt 0) {
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
    }

    $command.FilePath = (Get-Command 'msiexec.exe').Path

    ## The new name is 'Microsoft Defender for Endpoint' - to avoid confusions on Server 2016.
    $displayName = 'Microsoft Defender for (Windows Server|Endpoint)'
    $uninstallGUID = Get-UninstallGuid -DisplayName:$displayName

    $command.ArgumentList = if ($action -eq 'install') {
        if (-not (Test-Path -Path:$msi -PathType:leaf)) {
            Write-Error "$msi does not exist." -ErrorAction:Stop
        }
        @('/i', $msi)
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

    if (($action -eq 'install') -and ($null -ne $uninstallGUID)) {
        ## already installed, we need a reinstall
        Write-Host "Will force all files to be reinstalled, regardless of checksum or version."
        $command.ArgumentList += @('REINSTALLMODE=vamus', 'REINSTALL=ALL')
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
# MIIhXgYJKoZIhvcNAQcCoIIhTzCCIUsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDF1NZoGJyZkqP9
# UDA1zX5N3gjj7M5OymAdJR1IWpDWTKCCC14wggTrMIID06ADAgECAhMzAAAIMJFU
# sm0DDuykAAAAAAgwMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIwMTIxNTIyMzYyMloXDTIxMTIwMjIyMzYyMlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpgkY9Csw/
# uH67FTpWJI3MnC5fLg2eQvJzS/VPEAyOfdfKF3ngteszX/rledZW+v/X7ryyzdVC
# 97dVSXxHwOx08iQqcaTPpAyjp2FP9T7zU2K/O/L5oYGhsR9SQIxaShApXxjcw0Ms
# sSANnF1rM0+OgqrAdJeuBnqUC0rAnFefsWo1qOvdSuCTEd/Enlk9MJ8AxwzpbXnb
# lxz7d0Peh9A4l02NDnR2dAlArEbbsnvfOJS7ns9r5PeSyztpaYSBMalj54bcepDL
# S+RDUpeGuTrZERSWpe9YPeneVxugiQRPX4/5K2MAKqBVTCBrXrsm1jfUzfuKmVjg
# N9zvsYbaAx/BAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUu1eSysVlRSSolEd2tVtE7T6e63owUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDYzMDEyMB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFfK0IevjjEK/EC4xf9HY4ccUXgDK6xm
# h8pjDAXmYBnYfrFSU0E0f6t50BE+BjfAnnqxt7vexdVLu12tqo6Xtu+hxPNVudlW
# VPXJIkZGlnclxFv6Vcg+Pt5Vuh5ND17lHexYqNEiOrerImzFQNGHdhu+jFdVfZXS
# BUTzMQle6vJsWCDuZuKU7UzCEKMZGDxYFp2tnb0LFWn4c4iKjTpM1Hm4yVQdMHZv
# 7WdtGdWhiLxhTPm2NyXLSfiJ8ogTYXoYN3KJL2jNSe+sLek9SeY6gpaP0jSGV93R
# uBt79HRVT58d5MCw0+oHod6B9mIZSaaDk+2q54mzO7sA204Y3sVaw/UwggZrMIIE
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
# 7lah7Ou1TIUxghVWMIIVUgIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACDCRVLJtAw7spAAAAAAIMDANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgZLICXos0K1Fb6DBsxY9ZWCn8Bc73001UymDccVEM
# 8ggwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAfHbJA5Cu+
# FoiXvNnSj7XfUhAfkwwpVpG83DwwqBSxYenpraQJjYK/RLjgLcGM+pzdGKmQXSS9
# VvWQI4Gx1CiZxA5Yqt/Y6jhjxmRWmoqhwDF/EeFviHjXikBziXZA82eQnHycAEhj
# hVG6/1QKKjYI4q9VLhOkIEsnHXBKlrOGoA3n7SMoieJD48mitozWk/CMFoxZAxkR
# TQYFIWFVPRv/1Jg9tt7hiSbtpPznrQqRtdEAUxU78k7DOQMYrZVcbv2dBEfGmzeI
# CBEezdC/HI1xA4ezTfnj06Ye1WDYcHpDmHGh6oJDcDgsMrXXjNxOPcfYoFaC++QB
# GYznWnwUqm1eoYIS5TCCEuEGCisGAQQBgjcDAwExghLRMIISzQYJKoZIhvcNAQcC
# oIISvjCCEroCAQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIB
# QASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEICgrV6Pb
# O2ibdYQUPOB9A1DyNNuGpmHJnRa0Czd7ChvcAgZhRLpTN04YEzIwMjEwOTI4MDgx
# OTUwLjMxMVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIOPDCCBPEwggPZoAMC
# AQICEzMAAAFIoohFVrwvgL8AAAAAAUgwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjAxMTEyMTgyNTU2WhcNMjIwMjExMTgy
# NTU2WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
# A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046QUUyQy1FMzJCLTFBRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQD3/3ivFYSK0dGtcXaZ8pNLEARbraJewryi/JgbaKlq7hhFIU1EkY0HMiFRm2/W
# sukt62k25zvDxW16fphg5876+l1wYnClge/rFlrR2Uu1WwtFmc1xGpy4+uxobCEM
# eIFDGhL5DNTbbOisLrBUYbyXr7fPzxbVkEwJDP5FG2n0ro1qOjegIkLIjXU6qahd
# uQxTfsPOEp8jgqMKn++fpH6fvXKlewWzdsfvhiZ4H4Iq1CTOn+fkxqcDwTHYkYZY
# gqm+1X1x7458rp69qjFeVP3GbAvJbY3bFlq5uyxriPcZxDZrB6f1wALXrO2/IdfV
# EdwTWqJIDZBJjTycQhhxS3i1AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUhzLwaZ8O
# BLRJH0s9E63pIcWJokcwHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUw
# VgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9j
# cmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUF
# BwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIw
# ADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAZhKWwbMn
# C9Qywcrlgs0qX9bhxiZGve+8JED27hOiyGa8R9nqzHg4+q6NKfYXfS62uMUJp2u+
# J7tINUTf/1ugL+K4RwsPVehDasSJJj+7boIxZP8AU/xQdVY7qgmQGmd4F+c5hkJJ
# tl6NReYE908Q698qj1mDpr0Mx+4LhP/tTqL6HpZEURlhFOddnyLStVCFdfNI1yGH
# P9n0yN1KfhGEV3s7MBzpFJXwOflwgyE9cwQ8jjOTVpNRdCqL/P5ViCAo2dciHjd1
# u1i1Q4QZ6xb0+B1HdZFRELOiFwf0sh3Z1xOeSFcHg0rLE+rseHz4QhvoEj7h9bD8
# VN7/HnCDwWpBJTCCBnEwggRZoAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28
# dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQx
# H0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVH
# gc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbB
# Jx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL
# /W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8
# wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNV
# HQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsG
# AQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2Rl
# ZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkA
# YwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH
# 5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3H
# qJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQ
# yK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/t
# A6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguR
# JuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRC
# g7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDN
# p9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFr
# b3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN
# 4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N7
# 9ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zP
# WAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/edIhJEqGCAs4wggI3AgEBMIH4oYHQ
# pIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjpBRTJDLUUzMkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAhyuClrocWf4SIcRafAEX
# 1Rhs6zmggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkq
# hkiG9w0BAQUFAAIFAOT9EEswIhgPMjAyMTA5MjgxMTUzNDdaGA8yMDIxMDkyOTEx
# NTM0N1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5P0QSwIBADAKAgEAAgIP3QIB
# /zAHAgEAAgIQNzAKAgUA5P5hywIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AF9IeomdAutuXCaHbJArn0QHw22es8iSbrt2OiX5yDJHSlrpUEWFHBZFFfnb6Dy9
# LauiKT+Gi8u2xs56KZuXfCnTLg48cQNUCBKtOXcZuPhEgieVQO8DxcXs11wmNH2x
# CWMZBrU2JTRuGj1z3d6X5i7ohVepefsBH1f7ms5x/FISMYIDDTCCAwkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFIoohFVrwvgL8AAAAA
# AUgwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgd/bgEV5iaHB+BeBUfd6UgxtADTM6NbTl5sIp9z8M
# gYAwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCpkBrqjHmhvyYf5tTcTvD5
# Y4a+V79TwVV6T1aAwdto2DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABSKKIRVa8L4C/AAAAAAFIMCIEIFMXdF647gxyML1jCQ7L9kjf
# YmMJhS9fWDRgl02rPDwsMA0GCSqGSIb3DQEBCwUABIIBAI+3sfbv03sDoJatAR0A
# 239I2Hue52YKj1UWch4eMewKas0/KWyh77YfhTKWB7ByCMLNaCHzy/vWM4jQ/C99
# MJoNT7RP0eV6sd4+SsVCicVWNPr4G9M0j/8bcMWuFlx7D1bZU6M+CFZB6CfbQdIr
# XmMm06Bp9C9zLQt7PBKBVp8HD7NMEDFfiNFeEey1i9wgo9M0lQuFlW3oJHjCZFJy
# B4hwfodyvPZAfTMcSUxrMSIqxotyW6eDbIhBhwSefFxzqzwum9bkYZNu+BnQ76Px
# t7KgVA/OF45/8R5yq9MbyOcypfEXmz40DyeM64ib5ZBI5JpK3SNSvr1Jz2IaU0iC
# 3U8=
# SIG # End signature block
