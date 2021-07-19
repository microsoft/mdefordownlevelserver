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
            & logman.exe create trace $logBase -pf $wdprov -ets -o $tempFile *>$null
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
            param([string] $Uri, [string]$KB)
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
        Install-KB -Uri:'https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu' -KB:KB2999226
        ## telemetry dependency (needed by Sense service)
        Install-KB -Uri:'https://download.microsoft.com/download/4/E/8/4E864B31-7756-4639-8716-0379F6435016/Windows6.1-KB3080149-x64.msu' -KB:KB3080149
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
    $command.ArgumentList = if ($action -eq 'install') {
        if (-not (Test-Path -Path:$msi -PathType:leaf)) {
            Write-Error "$msi does not exist." -ErrorAction:Stop
        }
        @('/i', $msi)
    } else {
        @('/x', '{E9C10191-DB63-4973-81A7-6AF277D53456}')
    }

    if ($Log.IsPresent) {
        $command.ArgumentList += '/lvx*+', $tempMsiLog
    }

    if (-not $UI.IsPresent) {
        $command.ArgumentList += '/quiet'
    }
    
    if (($action -eq 'install') -and 
        (Test-Path -Path:'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E9C10191-DB63-4973-81A7-6AF277D53456}')) {
        ## already installed, we need a reinstall
        Write-Host "Will force all files to be reinstalled, regardless of checksum or version."
        $command.ArgumentList += @('REINSTALLMODE=vamus', 'REINSTALL="all"')
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
            & logman.exe stop $logBase -ets *>$null
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
# MIIhagYJKoZIhvcNAQcCoIIhWzCCIVcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQmwk1Xf1F5l7a
# k1RMKHHkCJQ2xZEBeZCiKjCH3kGlsqCCC14wggTrMIID06ADAgECAhMzAAAIMJFU
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
# 7lah7Ou1TIUxghViMIIVXgIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACDCRVLJtAw7spAAAAAAIMDANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgxByvRaiB1cjVXdkOHyr8MY1gqnX10hqA3nM4qoiw
# wf8wQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAu8a9YNJoX
# Nk5kcCPzN/BBxPaoZRYcWTi37rBaLdzJRCIMnqR56iA8+7TUkWuZ/WEsD9VcKh3T
# UuQ5n9fOYMJoVf5fbNa/2HPQVyAp0rtVVE14y07jsV1rqNWInlarEBZd9qP1/Pw8
# mtgkZ+1JEqIJwi3r26EoXMIpEZDVGmOz630O3+R0BQqYALTcRFxDz2AXLeFkPBGu
# 09ADvABLxaprDOMpMJSbBFWq201gb+NB1lLK7BSHHDnwNiohkudzxdPTUXeGUnld
# F0qEl4cwaobwL0A7AEpIin6/BKVgi8TTQESNbnvVM4ucxwHZdIQux6ePIfn51w+4
# cGhTWnsKmuJ9oYIS8TCCEu0GCisGAQQBgjcDAwExghLdMIIS2QYJKoZIhvcNAQcC
# oIISyjCCEsYCAQMxDzANBglghkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIB
# RASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIHrENpuw
# /T/8erFY+MM/CnE5dvAcx6u+JCxh9rv4/63jAgZg06IdDfIYEzIwMjEwNzE5MDgx
# MjI3LjQ1OVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGN0E2LUUyNTEtMTUwQTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDkQwggT1MIID
# 3aADAgECAhMzAAABWZ/8fl8s6vJDAAAAAAFZMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMDExNDE5MDIxNVoXDTIyMDQx
# MTE5MDIxNVowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjpGN0E2LUUyNTEtMTUwQTElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAK54xGHJZ8SHREtNIoBo9AG6Mro8gEZCt8WgV/mNdIt2tMOP3zVY
# U4+sRsImxTwfzJEDBWaTc7LxlEy/1302fRmd/R2pwnY7pyT90yvZAmQQLZ6D+faG
# Bwwhi5rre/tmBJdbAXFZ8qL2JDc4txBn30Mr1C8DFBdrIjwbP+i2RdAOaSwIs/xQ
# sMeZAz3v5j9VEdwq8+iM6YcLcqKrYAwP+OE58371ST5kj2f7quToeTXhSvDczKYr
# VokL3Zn0+KNAnbpp4rH1tXymmgXQcgVCz1E/Ey8NEsvZ1FjV5QP6ovDMT8YAo7Kz
# aYvT4Ix+xMVvW+1/1MnYaaoR8bLnQxmTZOMCAwEAAaOCARswggEXMB0GA1UdDgQW
# BBT20KmFRryt+uTrJ9eIwjyy6Tdj5zAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYb
# xTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IB
# AQCNkVQS6A+BhrfGOCAWo3KcuUa4estpzyn+ZLlkh0pJmAJp4EUDrLWsieYCf2oy
# oc8KjVMC+NHFFVvHLrSMhWnR5FtY6l3Z6Ur9ITBSz64j5wTRRE8vIpQiHVYjRVNP
# GR2tiqG5nKP5+sD0rZI464OFNz4n7erDJOpV7Im1L/sAwfX+GHoc4j5rfuAuQTFY
# 82sdYvtHM4LTxwV997uhlFs52oHapdFW1KXt6vMxEXnSX8soQfUd+M+Yq3J7udc6
# R941Guxfd6A0vecV56JjvmpCng4jRkquAeyf/dKmQUaR1fKvALBRAmZkAUtWijS/
# 3MkeQv/lUvHVo7GPFzJ/O3wJMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5m
# K1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcm
# gqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5
# hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/Vm
# wAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQB
# wSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQD
# AgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMw
# gYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9j
# cy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8A
# UABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQEL
# BQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJ
# at/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1
# mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbKegBv
# SzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/
# amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqW
# hqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua
# 2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46Pio
# SKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqH
# czsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw
# 07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P
# 6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSoYIC0jCCAjsC
# AQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGN0E2LUUyNTEtMTUwQTElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAKnbL
# AI8fhO58SCWrpZnXvXEZshGggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOSfFU0wIhgPMjAyMTA3MTkwMTAyMDVa
# GA8yMDIxMDcyMDAxMDIwNVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5J8VTQIB
# ADAKAgEAAgIgAQIB/zAHAgEAAgIRTzAKAgUA5KBmzQIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBAAth2qrgodEJWNvQ5QLAEMvrzZgHyMTuqcEZ/UGaXmdbZz6+
# KY3L/t1HbVd1PAFApaUDczhS4ovxDBtv0nlK5bXPkV2iH2eNSjybZZaju2e4LO+Z
# jlV5q4frYOI4tTSLuiwd9ZPyp6am8grghk9MVprghJC2fj6gjy82VCnYooYDMYID
# DTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFZ
# n/x+Xyzq8kMAAAAAAVkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgLFhrKvMeURx+L0UzVZr5WOZ7
# aMVnFk3ao1DBKaWxQiwwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABWBvP
# vzDmfNeSzmJT4+dGA+uj/qq7/fKkUn36rxND6DCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABWZ/8fl8s6vJDAAAAAAFZMCIEIHP6upOC
# bMUtM7XctsjD+hQp5ssv9L4PiMI2XmNj+qg3MA0GCSqGSIb3DQEBCwUABIIBAKLb
# o0aKms+RgBl3QiQCXCLKtCb9iXRtNMZjB6vH2PNnClzmqDCh4ly3RTKLIC0oB+D1
# 232aYd/oTzpopEhleAb7w6E7rxE2JGv8OSEh/1yXkbuAxqrI+4jcGHh//VM2CH/x
# Zlpq3+xWQLTMMs5Snb7ujg7OplTTU6QFa5FhnC+sRdcPSEoVSUvjNTEGI8522UVe
# nrmkwUG3EuAjiJd/6oAn5BHpz9eyXOLoqEysrJevtXlSTGbVwnsTZhaxhiqP7+TZ
# UWXovODt6b0DDM2Eh663qY+02aXCmvUebeEJO9Jau2CJa4Lt1E17nQJrai4IZTma
# Z46MxC8JkYys2B+48w0=
# SIG # End signature block
