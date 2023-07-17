<#
.SYNOPSIS
    Helper script for installing/uninstalling Microsoft Defender for Downlevel Servers.
.DESCRIPTION
    On install scenario:
        It first removes MMA workspace when RemoveMMA guid is provided.
        Next uninstalls SCEP if present and OS version is Server2012R2
        Next installs two hotfixes required by the MSI (if they are not installed)
        Next installs the Microsoft Defender for Downlevel Servers MSI (i.e. md4ws.msi)
        Finally, it runs the onboarding script, if provided using the parameter OnboardingScript. 
        Please use the script for Group Policy as it is non-interactive; the local onboarding script will fail.
    On uninstall scenario:
        It will run the offboarding script, if provided.
        Uninstalls the MSI unless IsTamperProtected is on.
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
    ## Used to pass extra arguments to Invoke-WebRequest calls used by this script (like WebSession, Proxy, ProxyCredential)
    [hashtable] $ExtraWebRequestOptions,
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

function Get-Digest {
    <#
.SYNOPSIS
    Returns an unique digest dependent on $sa array
#>
    param ([string[]] $sa)
    $sb = New-Object -TypeName:'System.Collections.Generic.List[byte]'
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    foreach ($element in $sa) {
        $null = $sb.AddRange($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($element)))
    }
    $hash = $sha256.ComputeHash($sb.ToArray())
    $sha256.Dispose()
    $rez = New-Object -TypeName:'System.Text.StringBuilder'
    foreach ($hb in $hash) {
        $null = $rez.Append($hb.ToString('X2'))
    }
    return $rez.ToString()
}

function Get-ScriptVersion {
    [CmdLetBinding()]
    param([string] $LiteralPath)
    ## DO NOT EDIT THIS BLOCK - BEGIN
    $version = @{
        Major    = '1'
        Minor    = '20230713'
        Patch    = '0'
        Metadata = '7A2876F7'
    }
    ## DO NOT EDIT THIS BLOCK - END
    [bool] $seen = $false
    $scriptLines = @(Get-Content -Path:$LiteralPath | ForEach-Object {
            $line = $_
            if (-not $seen) {            
                $seen = $line -ieq "#Copyright (C) Microsoft Corporation. All rights reserved."
                if ($line -match "^\s*Metadata\s*=\s*'([0-9A-F]{8})'") {
                    # skip it
                } else {
                    $line
                }
            }
        })
    
    $digest = (Get-Digest -sa:$scriptLines).Substring(0, 8)
    if ($digest -ne $version.Metadata) {
        $version.Patch = '1'
    }
    
    return "$($version.Major).$($version.Minor).$($version.Patch)+$digest"
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
        
        $pause = Get-Content -LiteralPath:$OnboardingScript | Where-Object { $_ -imatch '^pause$' }
        if ($pause.Length -ne 0) {
            ## Please read: https://github.com/microsoft/mdefordownlevelserver#project
            Exit-Install -Message:"Please use the onboarding script for Group Policy as it is non-interactive, $OnboardingScript might wait for user input" -ExitCode:$ERR_INVALID_SCRIPT_TYPE
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

        $pause = Get-Content -LiteralPath:$OffboardingScript | Where-Object { $_ -imatch '^pause$' }
        if ($pause.Length -ne 0) {
            ## Please read: https://github.com/microsoft/mdefordownlevelserver#project
            Exit-Install -Message:"Please use the offboarding script for Group Policy as it is non-interactive, $OffboardingScript might wait for user input" -ExitCode:$ERR_INVALID_SCRIPT_TYPE
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

function Start-TraceSession {
    [CmdLetBinding()]
    param()

    $guid = [guid]::NewGuid().Guid
    $wdprov = Join-Path -Path:$env:TEMP "$guid.temp"
    $tempFile = Join-Path -Path:$env:TEMP "$guid.etl"
    $etlLog = "$PSScriptRoot\$logBase.etl"
    $wppTracingLevel = 'WppTracingLevel'        
    $reportingPath = 'HKLM:\Software\Microsoft\Windows Defender\Reporting'
    $etlParams = @{
        ArgumentList = @($PSScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
    }

    if (-not (Test-IsAdministrator)) {
        # non-administrator should be able to install.
        $etlParams.Credential = Get-Credential -UserName:Administrator -Message:"Administrator credential are required for starting an ETW session:"
        $etlParams.ComputerName = 'localhost'
        $etlParams.EnableNetworkAccess = $true
    }

    if (Test-Path -LiteralPath:$etlLog -PathType:leaf) {
        if (Test-Path -LiteralPath:"$PSScriptRoot\$logBase.prev.etl") {
            Remove-Item -LiteralPath:"$PSScriptRoot\$logBase.prev.etl" -ErrorAction:Stop
        }
        Rename-Item -LiteralPath:$etlLog -NewName:"$logBase.prev.etl" -ErrorAction:Stop
    }

    $scmWppTracingKey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular'
    $scmWppTracingValue = 'TracingDisabled'
    $scmTracingDisabled = Get-RegistryKey -LiteralPath:$scmWppTracingKey -Name:$scmWppTracingValue
    if (1 -eq $scmTracingDisabled) {
        ## certain SCM issues could be investigated only if ebcca1c2-ab46-4a1d-8c2a-906c2ff25f39 is enabled.
        ## Unfortunatelly SCM does not register ebcca1c2-ab46-4a1d-8c2a-906c2ff25f39 when HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular[TracingDisabled] is (DWORD)1,
        ## therefore it cannot be enabled / disabled without a restart.
        Trace-Warning "Service Control Manager tracing is disabled (see $scmWppTracingKey[$scmWppTracingValue])"
    }

    Invoke-Command @etlparams -ScriptBlock: {
        param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath);
        ## enable providers
        $providers = @(
            @{Guid = 'ebcca1c2-ab46-4a1d-8c2a-906c2ff25f39'; Flags = 0x0FFFFFFF; Level = 0xff; Name = "SCM" },
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
            $jobParams = @{
                Name               = "Setting up $wppTracingLevel"
                ScriptBlock        = { 
                    param([string] $reportingPath, [string] $wppTracingLevel)
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

                    Set-RegistryKey -LiteralPath:$reportingPath -Name:$wppTracingLevel -Value:0 -ErrorAction:SilentlyContinue
                }
                ArgumentList       = @($reportingPath, $wppTracingLevel)
                ScheduledJobOption = New-ScheduledJobOption -RunElevated
            }
            try {
                $scheduledJob = Register-ScheduledJob @jobParams -ErrorAction:Stop
                $taskParams = @{
                    TaskName  = $scheduledJob.Name
                    Action    = New-ScheduledTaskAction -Execute $scheduledJob.PSExecutionPath -Argument:$scheduledJob.PSExecutionArgs
                    Principal = New-ScheduledTaskPrincipal -UserId:'NT AUTHORITY\SYSTEM' -LogonType:ServiceAccount -RunLevel:Highest
                }
                $scheduledTask = Register-ScheduledTask @taskParams -ErrorAction:Stop
                Start-ScheduledTask -InputObject:$scheduledTask -ErrorAction:Stop -AsJob | Wait-Job | Remove-Job -Force -Confirm:$false
                $SCHED_S_TASK_RUNNING = 0x41301
                do {
                    Start-Sleep -Milliseconds:10
                    $LastTaskResult = (Get-ScheduledTaskInfo -InputObject:$scheduledTask).LastTaskResult
                } while ($LastTaskResult -eq $SCHED_S_TASK_RUNNING)
            } catch {
                Trace-Warning "Error: $_"
            } finally {
                if ($scheduledJob) {
                    Unregister-ScheduledJob -InputObject $scheduledJob -Force
                }
                if ($scheduledTask) {
                    Unregister-ScheduledTask -InputObject $scheduledTask -Confirm:$false
                }
            }
            $wpp = Get-RegistryKey -LiteralPath:$reportingPath -Name:$wppTracingLevel
            if ($null -eq $wpp) {
                Trace-Warning "$reportingPath[$wppTracingLevel] could not be created"
            } else {
                Trace-Message "$reportingPath[$wppTracingLevel]=$wpp"
            }

            #Set-ItemProperty -LiteralPath:'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular' -Name:'TracingDisabled' -Value:0
            & logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile *>$null
            if (0 -eq $LASTEXITCODE) {
                Trace-Message "Tracing session '$logBase' started."
            } else {
                Trace-Warning "logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile exited with exitcode $LASTEXITCODE"
            }
        } catch {
            throw
        } finally {
            Remove-Item -LiteralPath:$wdprov -ErrorAction:Continue
        }
    }
    return $etlParams
}

@(
    @{ Name = 'ERR_INTERNAL'; Value = 1 }                   ## Not used.
    @{ Name = 'ERR_INSUFFICIENT_PRIVILEGES'; Value = 3 }    ## Are you running as Administrator?
    @{ Name = 'ERR_NO_INTERNET_CONNECTIVITY'; Value = 4 }   ## Are you behind a proxy? Is network on?
    @{ Name = 'ERR_CONFLICTING_APPS'; Value = 5 }           ## Not used.
    @{ Name = 'ERR_INVALID_PARAMETER'; Value = 6 }          ## Are you providing the right parameters to this script? Did you missmatch **On**boardingScript with an **Off**boarding script or vice-versa?
    @{ Name = 'ERR_UNSUPPORTED_DISTRO'; Value = 10 }        ## Is this a server SKU? Is this '2012 R2' or '2016' Server?
    @{ Name = 'ERR_UNSUPPORTED_VERSION'; Value = 11 }       ## Uninstall using the regular Administator account (Using System was fixed in Feb 2023)
    @{ Name = 'ERR_PENDING_REBOOT'; Value = 12 }            ## A dependent component requested a reboot.
    @{ Name = 'ERR_INSUFFICIENT_REQUIREMENTS'; Value = 13 } ## A requirement was not satisfied, cannot continue.
    @{ Name = 'ERR_UNEXPECTED_STATE'; Value = 14 }          ## Cannot handle the task in the current state of the product. Manual intervention is required.
    @{ Name = 'ERR_CORRUPTED_FILE'; Value = 15 }            ## All executable files (and this script) should be signed. Was one of the files (md4ws.msi) truncated?
    @{ Name = 'ERR_MSI_NOT_FOUND'; Value = 16 }             ## Is the MSI in the same directory like this file?
    @{ Name = 'ERR_ALREADY_UNINSTALLED'; Value = 17 }       ## Not used.
    @{ Name = 'ERR_DIRECTORY_NOT_WRITABLE'; Value = 18 }    ## Current directory should be writeable (to write the installation/uninstallation logs)
    @{ Name = 'ERR_MDE_NOT_INSTALLED'; Value = 20 }         ## Cannot uninstall something that is not installed.
    @{ Name = 'ERR_INSTALLATION_FAILED'; Value = 21 }       ## Not used.
    @{ Name = 'ERR_UNINSTALLATION_FAILED'; Value = 22 }     ## Not used.
    @{ Name = 'ERR_FAILED_DEPENDENCY'; Value = 23 }         ## Not used
    @{ Name = 'ERR_ONBOARDING_NOT_FOUND'; Value = 30 }      ## Check passed onboarding script path. Does it point to an existing file? 
    @{ Name = 'ERR_ONBOARDING_FAILED'; Value = 31 }         ## Onboarding script failed.
    @{ Name = 'ERR_OFFBOARDING_NOT_FOUND'; Value = 32 }     ## Check passed offboarding script path. Does it point to an existing file? 
    @{ Name = 'ERR_OFFBOARDING_FAILED'; Value = 33 }        ## Offboarding script failed.
    @{ Name = 'ERR_NOT_ONBOARDED'; Value = 34 }             ## Cannot offboard if not onboarded
    @{ Name = 'ERR_NOT_OFFBOARDED'; Value = 35 }            ## Cannot onboard if already onboarded.
    @{ Name = 'ERR_MSI_USED_BY_OTHER_PROCESS'; Value = 36 } ## md4ws.msi is opened by a process (orca.exe?!), preventing a successful installation.
    @{ Name = 'ERR_INVALID_SCRIPT_TYPE'; Value = 37 }       ## Onboarding/Offboading scripts shouldn't require any user interaction.
    @{ Name = 'ERR_TAMPER_PROTECTED'; Value = 38 }           ## Uninstallation cannot continue, since the product is still tamper protected.
    @{ Name = 'ERR_MDE_GROUP_POLICY_DISABLED'; Value = 39 }  ## HKLM:\Software\Policies\Microsoft\Windows Defender[DisableAntiSpyware] is set to 1.
) | ForEach-Object { 
    Set-Variable -Name:$_.Name -Value:$_.Value -Option:Constant -Scope:Script 
}

if (-not [System.Environment]::Is64BitOperatingSystem) {
    Exit-Install "Only 64 bit OSes (Server 2012 R2 or Server 2016) are currently supported by this script" -ExitCode:$ERR_UNSUPPORTED_DISTRO
} elseif (-not [System.Environment]::Is64BitProcess) {
    Trace-Warning "Current process IS NOT 64bit. Did you start a 'Windows Powershell (x86)'?!"
    $nativePowershell = "$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath:$nativePowershell -PathType:Leaf)) {
        Exit-Install "Cannot figure out 64 bit powershell location. Please run this script from a 64bit powershell." -ExitCode:$ERR_UNEXPECTED_STATE
    }
    
    [System.Collections.ArrayList] $argumentList = New-Object -TypeName:'System.Collections.ArrayList'
    $argumentList.AddRange(@('-NoProfile', '-NonInteractive', '-File', $MyInvocation.MyCommand.Path))
    if ($MyInvocation.BoundParameters.Count -gt 0) {
        function Get-EscapeString {
            param([string] $s)
            if ($null -ne $s -and ' ' -in $s -and $s[0] -ne '"') {
                "`"{0}'" -f $s
            } else {
                $s
            }
        }
        foreach ($boundparam in $MyInvocation.BoundParameters.GetEnumerator()) {
            if ($boundparam.Value -is [switch]) {
                if ($boundparam.Value.ToBool()) {
                    $null = $argumentList.Add($("-{0}" -f $boundparam.Key))
                }
            } else {
                $val = ''
                foreach ($k in ($boundparam.Value)) {
                    $val += if ($val.Length) { ',' } else { ':' }
                    $val += Get-EscapeString $k
                }
                $null = $argumentList.Add($("-{0}{1}" -f $boundparam.Key, $val))
            }
        }
        foreach ($k in $MyInvocation.UnboundArguments.GetEnumerator()) {
            $null = $argumentList.Add($("{0}" -f (Get-EscapeString $k)))
        }
    }
    
    $psArgumentList = $argumentList.ToArray()
    Trace-Message "Running $nativePowershell $psArgumentList"
    & $nativePowershell $psArgumentList
    if (-not $?) {
        Trace-Warning "$nativePowershell $psArgumentList exited with exitcode $LASTEXITCODE"
    }
    exit $LASTEXITCODE
}

Test-ExternalScripts
if ('Tls12' -notin [Net.ServicePointManager]::SecurityProtocol) {
    ## Server 2016/2012R2 might not have this one enabled and all Invoke-WebRequest might fail.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Trace-Message "[Net.ServicePointManager]::SecurityProtocol updated to '$([Net.ServicePointManager]::SecurityProtocol)'"
} 

if ($null -ne $ExtraWebRequestOptions) {
    ## validate ExtraWebRequestOptions hash
    [bool] $validExtraWebRequestOptions = $true
    foreach ($useOption in 'Uri', 'OutFile', 'ErrorAction', 'UseBasicParsing') {
        if ($ExtraWebRequestOptions.ContainsKey($useOption)) {
            Trace-Warning "Please remove $useOption from ExtraWebRequestOption hash and try again."
            $validExtraWebRequestOptions = $false
        }
    }
    if (-not $validExtraWebRequestOptions) {
        Exit-Install -Message:"Invalid parameter ExtraWebRequestOption (see the above warnings)" -ExitCode:$ERR_INVALID_PARAMETER
    }
}

$osVersion = Get-OSVersion

## make sure we capture logs by default.
[bool] $etl = -not $NoEtl.IsPresent
[bool] $log = -not $NoMSILog.IsPresent

[string] $msi = if ($DevMode.IsPresent -or ((Test-Path -Path:"$PSScriptRoot\md4ws-devmode.msi") -and -not (Test-Path -Path:"$PSScriptRoot\md4ws.msi"))) {
    ## This is used internally (never released to the public) by product team to test private builds.
    Join-Path -Path:$PSScriptRoot "md4ws-devmode.msi"
} else {
    Join-Path -Path:$PSScriptRoot "md4ws.msi"
}

$action = if ($Uninstall.IsPresent) { 'uninstall' }  else { 'install' }
$logBase = "$action-$env:COMPUTERNAME-$osVersion"

if ($etl -or $log) {
    ## make sure $PSSCriptRoot is writable. 
    $tempFile = Join-Path -Path:$PSScriptRoot "$([guid]::NewGuid().Guid).tmp"
    Set-Content -LiteralPath:$tempFile -Value:'' -ErrorAction:SilentlyContinue
    if (-not (Test-Path -LiteralPath:$tempFile -PathType:Leaf)) {
        Exit-Install "Cannot create $tempFile. Is $PSScriptRoot writable?" -ExitCode:$ERR_DIRECTORY_NOT_WRITABLE
    } else {
        Remove-Item -LiteralPath:$tempFile -ErrorAction:SilentlyContinue
        $tempFile = $null
    }
}

$etlParams = @{}

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

    ## Next 3 traces are here because they are helpful for investigations.
    $buildLabEx = Get-RegistryKey -LiteralPath:'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name:'BuildLabEx'
    Trace-Message "BuildLabEx: $buildLabEx"
    $editionID = Get-RegistryKey -LiteralPath:'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name:'EditionID'
    Trace-Message "EditionID: $editionID"
    $lastBootTime = (Get-CimInstance -ClassName:Win32_OperatingSystem).LastBootUpTime
    Trace-Message "LastBootUpTime: $($lastBootTime.ToString('yy/MM/ddTHH:mm:ss.fff'))"
    Trace-Message "CurrentTime   : $((Get-Date).ToString('yy/MM/ddTHH:mm:ss.fffzzz'))"
    $scriptPath = $MyInvocation.MyCommand.Path
    Trace-Message "$($MyInvocation.MyCommand.Name) version: $(Get-ScriptVersion -LiteralPath:$scriptPath)"

    if ($action -eq 'install') {
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            $windefend = Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue
            $wdnissvc = Get-Service -Name:'WdNisSvc' -ErrorAction:SilentlyContinue
            $wdfilter = Get-Service -Name:'WdFilter' -ErrorAction:SilentlyContinue
            if ($windefend -and -not $wdnissvc -and -not $wdfilter) {
                ## workaround for ICM#278342470 (or VSO#37292177). Fixed on MOCAMP version 4.18.2111.150 or newer.
                if ($windefend.Status -eq 'Running') {
                    Exit-Install "Please reboot this computer to remove 'WinDefend' Service" -ExitCode:$ERR_PENDING_REBOOT
                } elseif ($windefend.Status -eq 'Stopped') {
                    $winDefendServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend'
                    if (Test-Path -LiteralPath:$winDefendServicePath) {
                        $imagePath = Get-RegistryKey -LiteralPath:$winDefendServicePath -Name:'ImagePath'
                        Trace-Message "WinDefend service is Stopped. ImagePath is $imagePath. Trying to remove $winDefendServicePath"
                        Remove-Item -LiteralPath:$winDefendServicePath -Force -Recurse -ErrorAction:SilentlyContinue
                        if (Test-Path -LiteralPath:$winDefendServicePath) {
                            Exit-Install "Cannot remove $winDefendServicePath" -ExitCode:$ERR_UNEXPECTED_STATE
                        }
                    } else {
                        Trace-Warning "WinDefend service is stopped but $winDefendServicePath is gone. This usually happens when running this script more than once without restarting the machine."
                    }
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
                    Invoke-WebRequest -Uri:$Uri -OutFile:$outFile -ErrorAction:Stop @ExtraWebRequestOptions
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

            $disableAntiSpywareGP = Get-RegistryKey -LiteralPath:'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name:'DisableAntiSpyware'
            if ($disableAntiSpywareGP) {
                Exit-Install "Remove(or change it to 0) HKLM:\Software\Policies\Microsoft\Windows Defender[DisableAntiSpyware] and try installing again." -ExitCode:$ERR_MDE_GROUP_POLICY_DISABLED
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
            $imageName = (Get-ItemPropertyValue -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
            $currentVersion = Get-FileVersion -File:$imageName
            if ($currentVersion -lt '4.18.23050.5') {
                Trace-Warning "Current platform version is $currentVersion, a platform update is needed."
            }

            if ($windefendStatus -ne 'Running') {
                $disableAntiSpywareGP = Get-RegistryKey -LiteralPath:'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name:'DisableAntiSpyware'
                if ($disableAntiSpywareGP) {
                    ## ICM#383475289 - WinDefend disabled via GP
                    Exit-Install "Remove(or change it to 0) HKLM:\Software\Policies\Microsoft\Windows Defender[DisableAntiSpyware] and try installing again." -ExitCode:$ERR_MDE_GROUP_POLICY_DISABLED
                }

                if ($currentVersion -lt '4.18.2102.4' -and $windefendStatus -eq 'Stopped') {
                    ## ICM#391597247. Possible scenarios:
                    ## - WinDefend was disabled via 'mpcmdrun.exe disableservice' sometimes between 2017 to 2021.
                    ## - or the platform was reset to inbox version and after that disabled.
                    $isDisabled = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).StartType -eq 'Disabled'
                    if ($isDisabled) {
                        #define SERVICE_AUTO_START 0x00000002
                        #define SERVICE_DISABLED   0x00000004
                        Set-ItemProperty -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:'Start' -Value:2 -ErrorAction:SilentlyContinue
                        $isDisabled = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).StartType -eq 'Disabled'
                        if ($isDisabled) {
                            Exit-Install "Cannot enable 'WinDefend' service" -ExitCode:$ERR_UNEXPECTED_STATE
                        }
                        Trace-Message "'WinDefend' service has been enabled."
                    }
                }
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
                            
                            try {
                                $latestVersion = ([xml]((Invoke-WebRequest -UseBasicParsing -Uri:"$uri&action=info" @ExtraWebRequestOptions).Content)).versions.platform
                            } catch {
                                Trace-Warning "Error: $_"
                                Exit-Install "Cannot download the latest $updatePlatformBaseName. Please download it from $uri under $PSScriptRoot\$updatePlatformBaseName" -ExitCode:$ERR_NO_INTERNET_CONNECTIVITY
                            }

                            if ($latestVersion -lt $msiVersion) {
                                Trace-Warning "Changing msiVersion from $msiVersion to $latestVersion"
                                $msiVersion = $latestVersion
                            }
                            
                            if ($latestVersion -gt $currentVersion) {
                                Trace-Message "Downloading latest $updatePlatformBaseName (version $latestVersion) from $uri"
                                $deleteUpdatePlatform = $true
                                $updatePlatform = Join-Path -Path:$env:TEMP $updatePlatformBaseName
                                Invoke-WebRequest -UseBasicParsing -Uri:$uri -OutFile:$updatePlatform @ExtraWebRequestOptions
                            } else {
                                Trace-Message "Running platform is up-to-date"
                            }
                        }
                        
                        if (Test-Path -LiteralPath:$updatePlatform -PathType:Leaf) {
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

            $krnlACL = Get-Acl -Path:"$env:SystemRoot\System32\ntoskrnl.exe"
            if ($krnlACL.Owner -ne 'NT SERVICE\TrustedInstaller') {
                ## See ICM#379926141 - unable to install md4ws.msi "Unsupported OS version"
                $wrongOwner = $krnlACL.Owner
                $ti = New-Object -TypeName:System.Security.Principal.NTAccount('NT SERVICE\TrustedInstaller')
                $krnlACL.SetOwner($ti)
                Set-Acl -Path:"$env:SystemRoot\System32\ntoskrnl.exe" -AclObject:$krnlACL
                Trace-Warning "Current owner for $env:SystemRoot\System32\ntoskrnl.exe changed from '$wrongOwner' to '$($krnlACL.Owner)'"
            }
        } else {
            Exit-Install "Unsupported OS version: $osVersion" -ExitCode:$ERR_UNSUPPORTED_DISTRO
        }
    }
    
    [hashtable] $etlParams = @{}
    $onboardedSense = Get-RegistryKey -LiteralPath:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
    if ($OffboardingScript.Length -gt 0 -and ($action -eq 'uninstall' -or $null -ne $uninstallGUID)) {
        if (2 -ne $onboardedSense) {
            Exit-Install -Message:"Sense Service is not onboarded, nothing to offboard." -ExitCode:$ERR_NOT_ONBOARDED
        }
        Trace-Message "Invoking offboarding script $OffboardingScript"
        $scriptPath = if ($OffboardingScript.Contains(' ') -and -not $OffboardingScript.StartsWith('"')) {
            '"{0}"' -f $OffboardingScript
        } else {
            $OffboardingScript
        }
        ## Sense service is delay starting and for offboarding to work without false positives Sense has to run. 
        $senseService = Get-Service -Name:Sense
        if ($senseService.Status -ne 'Running') {
            $senseService = Start-Service -Name:Sense -ErrorAction:SilentlyContinue
        }
        if ($senseService) {
            Trace-Message "Sense service status is '$($senseService.Status)'"             
        }

        if ($etl) {
            ## Offboard might fail due to WinDefend changes.
            $etlParams = Start-TraceSession
        }
    
        $exitCode = Measure-Process -FilePath:$((Get-Command 'cmd.exe').Path) -ArgumentList:@('/c', $scriptPath) -PassThru
        if (0 -eq $exitCode) {
            Trace-Message "Offboarding script $OffboardingScript reported success."
            $onboardedSense = Get-RegistryKey -LiteralPath:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
            $endWait = (Get-Date) + 30 * [timespan]::TicksPerSecond
            $traceWarning = $true
            while (2 -eq $onboardedSense -and (Get-Date) -lt $endWait) {
                if ($traceWarning) {
                    $traceWarning = $false
                    Trace-Warning "HKLM:SYSTEM\CurrentControlSet\Services\Sense[Start] is still 2. Waiting for it to change..."
                }
                Start-Sleep -Milliseconds:100
                $onboardedSense = Get-RegistryKey -LiteralPath:'HKLM:SYSTEM\CurrentControlSet\Services\Sense' -Name:'Start'
            }
            if (2 -eq $onboardedSense) {
                Exit-Install "`'HKLM:SYSTEM\CurrentControlSet\Services\Sense[Start]`' is still 2(onboarded) so offboarding failed" -ExitCode:$ERR_OFFBOARDING_FAILED
            }
        } else {
            Exit-Install "Offboarding script returned $exitCode." -ExitCode:$exitCode
        }       
    }

    if ($action -eq 'uninstall') {
        [bool] $isTamperProtected = (Get-MpComputerStatus -ErrorAction:SilentlyContinue).IsTamperProtected
        if ($isTamperProtected) {
            # This is already encoded in the product, added here for clarity.
            Exit-Install "Tamper protection is still enabled. Please disable it (or boot in 'Safe Mode') before uninstalling the product." -ExitCode:$ERR_TAMPER_PROTECTED
        }

        & logman.exe query "SenseIRTraceLogger" -ets *>$null
        if (0 -eq $LASTEXITCODE) {
            Trace-Warning "SenseIRTraceLogger still present, removing it!"
            & logman.exe stop -n "SenseIRTraceLogger" -ets *>$null
            if (0 -ne $LASTEXITCODE) {
                Trace-Warning "SenseIRTraceLogger could not be removed, exitCode=$LASTEXITCODE"
            }
        }
        
        try {
            # MsSense executes various Powershell scripts and these ones start executables that are not tracked anymore by the MsSense.exe or SenseIr.exe
            # This is mitigated in the latest package but for previously installed packages we have to implement this hack to have a successful uninstall.
            $procs = Get-Process -ErrorAction:SilentlyContinue
            foreach ($proc in $procs) {
                foreach ($m in $proc.Modules.FileName) {
                    if ($m.StartsWith("$env:ProgramFiles\Windows Defender Advanced Threat Protection\") -or
                        $m.StartsWith("$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\")) {
                        Trace-Warning "Terminating outstanding process $($proc.Name)(pid:$($proc.Id))"
                        Stop-Process -InputObject:$proc -Force -ErrorAction:Stop
                        break
                    }
                }
            }
        } catch {
            Trace-Warning "Error: $_"
            Exit-Install "Offboarding left processes that could not be stopped" -ExitCode:$ERR_OFFBOARDING_FAILED
        }

        ## Once in a long while (after an UpdateSenseClient.exe update) MsSecFlt cannot be unloaded anymore.
        ## a kernel dump is needed to investigate this issue so this block stays here until we are lucky.
        $msSecFlt = Get-Service -Name:'MsSecFlt' -ErrorAction:SilentlyContinue
        if ($null -ne $msSecFlt -and $msSecFlt.Status -eq 'Running' -and -not $msSecFlt.CanStop) {
            Trace-Warning "Service '$($msSecFlt.Name)' cannot be stopped, reboot is required"
            Exit-Install "Please restart this machine to complete '$($msSecFlt.Name)' service removal" -ExitCode:$ERR_PENDING_REBOOT
        }

        # dealing with current powershell session that error out after this script finishes.
        foreach ($name in 'ConfigDefender', 'Defender') {
            $defender = Get-Module $name -ErrorAction:SilentlyContinue
            if ($defender) {
                Remove-Module $defender
                Trace-Message 'Defender module unloaded.'
                break
            }
        }

        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            if (Test-CurrentUserIsInRole 'S-1-5-18') {
                if ($null -ne $uninstallGUID) {
                    $displayVersion = Get-RegistryKey -LiteralPath:"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${uninstallGUID}" -Name:'DisplayVersion'
                    if ($displayVersion -contains '4.18.' -and $displayVersion -lt '4.18.60326') {
                        # See ICM#337407672 - This will be (or has been) fixed with build 4.18.2301.126 such that newer md4ws.msi could be uninstalled from system account. 
                        # Older msis have to be uninstalled from a normal Administrator account
                        Exit-Install "Uninstallation of version $displayVersion is not supported from System account. Try uninstalling from a regular Administrator account" -ErrorAction:$ERR_UNSUPPORTED_VERSION
                    } else {
                        Trace-Warning "Running uninstall from System account - UninstallGUID is $uninstallGUID"
                    }
                } else {
                    Trace-Warning "Running uninstall from System account"
                }
            }

            $needWmiPrvSEMitigation = if ($null -ne $uninstallGUID) {
                $displayVersion = Get-RegistryKey -LiteralPath:"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${uninstallGUID}" -Name:'DisplayVersion'
                ## newer versions handle this via custom action inside the MSI
                $displayVersion -lt '4.18.60321'
            } else {
                $true
            }
            
            if ($needWmiPrvSEMitigation) {
                # dealing with WmiPrvSE.exe keeping ProtectionManagement.dll in use (needed only on Server 2012 R2)
                Get-Process -Name:'WmiPrvSE' -ErrorAction:SilentlyContinue | ForEach-Object {
                    if ($_.MainModule.FileName -ne "$env:SystemRoot\system32\wbem\wmiprvse.exe") {
                        return
                    }
                    [string] $loadedModule = ''                    
                    foreach ($m in $_.Modules.FileName) {
                        if ($m.StartsWith("$env:ProgramFiles\Windows Defender\") -or 
                            $m.StartsWith("$env:ProgramData\Microsoft\Windows Defender\Platform\")) {
                            $loadedModule = $m
                            break
                        }
                    }
                    if ($loadedModule.Length -gt 0) {
                        Trace-Warning "Terminating $($proc.Name)(pid:$($proc.Id)) because has '$loadedModule' in use"
                        Stop-Process $_.Id -Force -ErrorAction:Stop
                    }
                }
            }
        }
    } 
    
    if (2 -eq $onboardedSense) {
        # all MSI operations (installing, uninstalling, upgrading) should be performed while Sense is offboarded.
        Exit-Install -Message:"Sense Service is onboarded, offboard before reinstalling(or use -OffboardingScript with this script)" -ExitCode:$ERR_NOT_OFFBOARDED
    }

    $argumentList = if ($action -eq 'install') {
        if (-not (Test-Path -LiteralPath:$msi -PathType:leaf)) {
            Exit-Install "$msi does not exist. Please download latest $(Split-Path -Path:$msi -Leaf) into $PSScriptRoot and try again." -ExitCode:$ERR_MSI_NOT_FOUND
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
    
    if ($etl -and 0 -eq $etlParams.Count) {
        ## start ETW session if not already.
        $etlParams = Start-TraceSession
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
    if ($etlParams.ContainsKey('ArgumentList')) {
        Invoke-Command @etlparams -ScriptBlock: {
            param($ScriptRoot, $logBase, $wdprov, $tempFile, $etlLog, $wppTracingLevel, $reportingPath)
            & logman.exe stop -n $logBase -ets *>$null
            if (0 -eq $LASTEXITCODE) {
                Trace-Message "Tracing session '$logBase' stopped."
            } else {
                Trace-Warning "logman.exe stop -n $logBase -ets returned $LASTEXITCODE"
            }

            try {                
                $jobParams = @{
                    Name               = "Cleanup $wppTracingLevel"
                    ScriptBlock        = { 
                        param($reportingPath, $wppTracingLevel)
                        Remove-ItemProperty -LiteralPath:$reportingPath -Name:$wppTracingLevel -ErrorAction:SilentlyContinue 
                    }
                    ArgumentList       = @($reportingPath, $wppTracingLevel)
                    ScheduledJobOption = New-ScheduledJobOption -RunElevated
                }
                $scheduledJob = Register-ScheduledJob @jobParams -ErrorAction:Stop
                $taskParams = @{
                    TaskName  = $scheduledJob.Name
                    Action    = New-ScheduledTaskAction -Execute $scheduledJob.PSExecutionPath -Argument:$scheduledJob.PSExecutionArgs
                    Principal = New-ScheduledTaskPrincipal -UserId:'NT AUTHORITY\SYSTEM' -LogonType:ServiceAccount -RunLevel:Highest
                }
                $scheduledTask = Register-ScheduledTask @taskParams -ErrorAction:Stop
                Start-ScheduledTask -InputObject:$scheduledTask -ErrorAction:Stop -AsJob | Wait-Job | Remove-Job -Force -Confirm:$false
                $SCHED_S_TASK_RUNNING = 0x41301
                do {
                    Start-Sleep -Milliseconds:10
                    $LastTaskResult = (Get-ScheduledTaskInfo -InputObject:$scheduledTask).LastTaskResult
                } while ($LastTaskResult -eq $SCHED_S_TASK_RUNNING)
                $wpp = Get-RegistryKey -LiteralPath:$reportingPath -Name:$wppTracingLevel
                if ($null -eq $wpp) {
                    Trace-Message "$reportingPath[$wppTracingLevel] removed"
                }
            } catch {
                Trace-Warning "Error: $_"
            } finally {
                if ($scheduledJob) {
                    Unregister-ScheduledJob -InputObject $scheduledJob -Force
                }
                if ($scheduledTask) {
                    Unregister-ScheduledTask -InputObject $scheduledTask -Confirm:$false
                }
            }

            Move-Item -LiteralPath:$tempFile -Destination:$etlLog -ErrorAction:Continue
            Trace-Message  "ETL file: '$etlLog'."    
        }
    } else {
        Trace-Message "No etl file generated."
    }

    if ($log -and (Test-Path -LiteralPath:$tempMsiLog -PathType:Leaf)) {
        Move-Item -LiteralPath:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Trace-Message "Msi log: '$msiLog'"
    } else {
        Trace-Message "No log file generated."
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.

# SIG # Begin signature block
# MIIlfQYJKoZIhvcNAQcCoIIlbjCCJWoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChQ4rkRrjtOYh9
# +/oPfccxu33WhSFhQPTfUqzP9QzJr6CCC2IwggTvMIID16ADAgECAhMzAAAKc/FU
# CYZWEHhHAAAAAApzMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMDIxNjE5MDA0NFoXDTI0MDEzMTE5MDA0NFowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0znTAytEY
# jN+IOBOLzQZ+M2rbqzlt9u2/9snBb9X4YHf6QwG+ccLIj8wyn0+lHLagkHw2kQ9h
# nymXhJLv+fVpMlEyNigGyAmH0rM1crsQoUToGaq2Um28OhUm9CRxqGGl6rvmZ1Q4
# 5ExvAq6/gE0JUkmJyPpRHZuJIdmceH0DE0ACeCj9jthtdrtNsDCGQcjvqZh0sSXi
# uwxX/pgvc8mHEJIfqhK95dTu0CVz7qkhOCM1ePU8gOWbC17NAptqGeps0v5efEEy
# rYvzxee52fUO7R2it8JtXDuJ1r9X7TDLBPlSj4ZejWMS9ZelvGSrv98UyJzainia
# Q81xAGxR++BdAgMBAAGjggF3MIIBczAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUrUcDAOl/pmci0aNJQcKExaMhzmQwVAYDVR0RBE0w
# S6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEWMBQGA1UEBRMNMjMwMDI4KzUwMDE5MTAfBgNVHSMEGDAWgBTRT6mKBwjO
# 9CQYmOUA//PWeR03vDBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5j
# cmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA/Xky5Ry4E9i8YZgEukoocB2Sh
# aEZEhCUE3WnXfaylCZVPoc/6VsOAF4aLBk4/mxAq7HUjYZPhBMZ1c8bsCBBnj3aK
# YiFLzX9SzfwnTqH7giRpBGfaiU1P+I8R6LtUb07hO1KDIJY4T//2wzvqze8l3nn+
# jh9O5tWA+832F/jj9VObTTGx5eBKcDQmF/U7EgWSVWGDeHFRpJMpcQJTLAMwkbMR
# vijbfdR7A+48ENPN+Sjfln0AW2Zb+i4FP0chgRtdY4szEybOAZAVpF4Wp/49h/Wz
# Pd5EK/OqdKwr7Z1/EeKzvR4RgdkUsodwym3KnoEC/SbhO/Va/T5fh3araOJ+MIIG
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
# 3gI/h+5WoezrtUyFMYIZcTCCGW0CAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENB
# IDIwMTACEzMAAApz8VQJhlYQeEcAAAAACnMwDQYJYIZIAWUDBAIBBQCgga4wGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIPhjsxSowDhF9mVVgMQp6KQIAfR/eeeMttuX
# ZTAjN4DqMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEa
# gBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAD7Yg
# +3noLh6sUb0qVVsVa9SLksqBkQ8ORtjeXt/NJSsz9bn+KGkuf47uBwI+9uPANsTh
# sv1YyUm9JoeKRQ7c1tdTGA/a5k5072DAkVxl6xDnv0tUvDgtI4JsdOaF8uWOswVY
# AF4mReR4Z7tv45zoU3vE6YJCiY2S2k4XfgUYS1sPjYVvdx1ATlFfJWy47ZXDoWLk
# y3bZ3c1YZ7vhdphvrxEs9tVS6J9KYm6AOVbckI8OQYBl+//JmgjPxQy/33f06xIu
# iAVYN6l+OcOR3oBU26vkZvP+0tOOiFD7oosoOmrNdux69aKt1nOhNcLi3iACswFv
# NoS5Do/+quSl6JY5z6GCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3
# DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRAB
# BKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCe
# gC4S/DIHox8GJLjl27oVy05E2osoFXHdlVqUVVixqgIGZLAclq3wGBMyMDIzMDcx
# NTA5NDY1MS40NzRaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVy
# YXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxMkJDLUUzQUUtNzRFQjEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVcwggcMMIIE
# 9KADAgECAhMzAAAByk/Cs+0DDRhsAAEAAAHKMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDE0MFoXDTI0MDIw
# MjE5MDE0MFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjEyQkMtRTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAwwGcq9j50rWEkcLSlGZLweUVfxXRaUjiPsyaNVxPdMRs3CVe58siu/Ek
# aVt7t7PNTPko/s8lNtusAeLEnzki44yxk2c9ekm8E1SQ2YV9b8/LOxfKapZ8tVlP
# yxw6DmFzNFQjifVm8EiZ7lFRoY448vpcbBD18qjYNF/2Z3SQchcsdV1N9Y6V2WGl
# 55VmLqFRX5+dptdjreBXzi3WW9TsoCEWcYCBK5wYgS9tT2SSSTzae3jmdw40g+LO
# IyrVPF2DozkStv6JBDPvwahXWpKGpO7rHrKF+o7ECN/ViQFMZyp/vxePiUABDNqz
# EUI8s7klYmeHXvjeQOq/CM3C/Y8bj3fJObnZH7eAXvRDnxT8R6W/uD1mGUJvv9M9
# BMu3nhKpKmSxzzO5LtcMEh2tMXxhMGGNMUP3DOEK3X+2/LD1Z03usJTk5pHNoH/g
# DIvbp787Cw40tsApiAvtrHYwub0TqIv8Zy62l8n8s/Mv/P764CTqrxcXzalBHh+X
# y4XPjmadnPkZJycp3Kczbkg9QbvJp0H/0FswHS+efFofpDNJwLh1hs/aMi1K/ozE
# v7/WLIPsDgK16fU/axybqMKk0NOxgelUjAYKl4wU0Y6Q4q9N/9PwAS0csifQhY1o
# oQfAI0iDCCSEATslD8bTO0tRtqdcIdavOReqzoPdvAv3Dr1XXQ8CAwEAAaOCATYw
# ggEyMB0GA1UdDgQWBBT6x/6lS4ESQ8KZhd0RgU7RYXM8fzAfBgNVHSMEGDAWgBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAC
# hlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
# dCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQDY0HkqCS3K
# uKefFX8/rm/dtD9066dKEleNqriwZqsM4Ym8Ew4QiqOqO7mWoYYY4K5y8eXSOHKN
# XOfpO6RbaYj8jCOcJAB5tqLl5hiMgaMbAVLrl1hlix9sloO45LON0JphKva3D6AV
# KA7P78mA9iRHZYUVrRiyfvQjWxmUnxhis8fom92+/RHcEZ1Dh5+p4gzeeL84Yl00
# Wyq9EcgBKKfgq0lCjWNSq1AUG1sELlgXOSvKZ4/lXXH+MfhcHe91WLIaZkS/Hu9w
# dTT6I14BC97yhDsZWXAl0IJ801I6UtEFpCsTeOyZBJ7CF0rf5lxJ8tE9ojNsyqXJ
# KuwVn0ewCMkZqz/cEwv9FEx8QmsZ0ZNodTtsl+V9dZm+eUrMKZk6PKsKArtQ+jHk
# fVsHgKODloelpOmHqgX7UbO0NVnIlpP55gQTqV76vU7wRXpUfz7KhE3BZXNgwG05
# dRnCXDwrhhYz+Itbzs1K1R8I4YMDJjW90ASCg9Jf+xygRKZGKHjo2Bs2XyaKuN1P
# 6FFCIVXN7KgHl/bZiakGq7k5TQ4OXK5xkhCHhjdgHuxj3hK5AaOy+GXxO/jbyqGR
# qeSxf+TTPuWhDWurIo33RMDGe5DbImjcbcj6dVhQevqHClR1OHSfr+8m1hWRJGlC
# 1atcOWKajArwOURqJSVlThwVgIyzGNmjzjCCB3EwggVZoAMCAQICEzMAAAAVxedr
# ngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4
# MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qls
# TnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLA
# EBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrE
# qv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyF
# Vk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1o
# O5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg
# 3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2
# TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07B
# MzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJ
# NmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6
# r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+
# auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3
# FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUH
# AgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0
# b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMA
# dQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
# gBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRf
# MjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL
# /Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu
# 6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5t
# ggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfg
# QJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8s
# CXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCr
# dTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZ
# c9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2
# tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8C
# wYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9
# JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDB
# cQZqELQdVTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1F
# M0FFLTc0RUIxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wi
# IwoBATAHBgUrDgMCGgMVAKOO55cMT4syPP6nClg2IWfajMqkoIGDMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDoXJU0
# MCIYDzIwMjMwNzE1MTE0NzAwWhgPMjAyMzA3MTYxMTQ3MDBaMHcwPQYKKwYBBAGE
# WQoEATEvMC0wCgIFAOhclTQCAQAwCgIBAAICEWMCAf8wBwIBAAICE7wwCgIFAOhd
# 5rQCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAweh
# IKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAquoYmzuEu9a8lYCfVSIeC
# yojEh2yxKXXuT6INo8ky69e+c6Np7DKbUy+9Rn5C+nuhmyWjeyaH8/Yf3set+r/c
# /Vjh3AjP+AXZVH4TfDEeDuTSgqxL1fIhfisl1vmPu7r73AnWAsyyZCjV+EE+GE8R
# R/4VAX+bEHgbQyfMXXrv0zGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAAByk/Cs+0DDRhsAAEAAAHKMA0GCWCGSAFlAwQCAQUA
# oIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIE
# IA/3+NfZFKR5U9PZ+0vppbZU9meW0iuVqZGl61OHluWnMIH6BgsqhkiG9w0BCRAC
# LzGB6jCB5zCB5DCBvQQgEz0b85vrVU2slZAk4jt1SDEk6IzZAwVCoWwF3KzcGuAw
# gZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcpPwrPt
# Aw0YbAABAAAByjAiBCCL+/toWRNHdNX3lNJHdB8inQ6quqvAoEERAoPQy45bBjAN
# BgkqhkiG9w0BAQsFAASCAgCSBW7H2jCJw258D2ydOEWbvjrF7eb/jXCxnEP4oQbh
# r/aDyJW3zxzddrPyZgWjhi2HY+snIHUWFtuiHcZuLshTzMyPndMso+h6a1W+vkts
# O8sKSRxkrOLL30lIgLlyh2KfUGzURyZHZ0/CaFBy3uezVdFMTNqikJiq8flkQu94
# 1U338XqleCv+ZSQzmORFDuq36Q1IrAkP84NjW24+5guZ+QI1CnSR1VuJMbotZ04c
# 64M8olAQ7H9rhJwpqvLEA3IhPCa7tNaiHhMvDABB3vNlyf08jXYOd+5r1cc/iIv2
# u0O7Ye5MNI8w95HoACQy6JEkEV8FQeNSR9qhMMS5qYj8/2xhGC1NnTczJfu2Xzby
# +DbY2stxs/y7SY/SRPCHfIyD/K+v5J7CVrHWiEQV56u2KsZEoyVFhvjtWSHK0gpv
# ZdTDoDrWZc4Vqcp6XZoYI63tJCZ61pJirS78mz0r6fPYYQBR7hMoh17aAukqnvfv
# U+a1mCHib+dWdC3A4FRErvbJTtCZFi+yi1mEeWSSMi29BGlSf+8qi8yffkMItVZh
# sx4eDFyb8TejjGS2XpDWZu2lCd/uR1P5If7PDVcT3MUz9pttat4d+nCWgCexeUl9
# y2xHNIzXJjjfcbxW/fncj3IIge/XwQfp89z30+hlV3zmiLtgKt6rwwZh+5e1VcG1
# 3A==
# SIG # End signature block
