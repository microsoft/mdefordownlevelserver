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
    [hashtable] $ExtraWebRequestOptions = @{},
    [Parameter(ParameterSetName = 'install')]
    [Parameter(ParameterSetName = 'uninstall')]
    ## Disable ETL logging
    [switch] $NoEtl)
 

function Get-CommandLine {
    <#
.synopsis
    Returns the equivalent command line used to invoke a script
.DESCRIPTION
    Returns the equivalent command line used to invoke a script
.EXAMPLE
    Get-CommandLine $PSCmdLet.MyInvocation
#>
    [CmdletBinding()]
    [OutputType([string])]
    ## Usually $PSCmdLet.MyInvocation.
    param([Parameter(ValueFromPipeline = $true, Position = 0)] [System.Management.Automation.InvocationInfo] $info)

    process {
        function EscapeString {
            param([string] $s)
            if ($null -ne $s -and ' ' -in $s -and $s[0] -ne '"') {
                "`"{0}'" -f $s
            }
            else {
                $s
            }
        }

        [string] $commandLine = ''
        if ($null -ne $info) {
            $commandLine = EscapeString $info.MyCommand.Name
            foreach ($boundparam in $info.BoundParameters.GetEnumerator()) {
                $val = ''
                foreach ($k in ($boundparam.Value)) {
                    $val += if ($val.Length) { ',' } else { ':' }
                    $val += if ($k -is [switch]) {
                        if ($k.ToBool()) { '$true' } else { '$false' }
                    }
                    else {
                        EscapeString $k
                    }
                }
                $commandLine += " -{0}{1}" -f $boundparam.Key, $val
            }

            foreach ($k in $info.UnboundArguments.GetEnumerator()) {
                $commandLine += " {0}" -f (EscapeString $k)
            }
        }

        return $commandLine
    }
}    

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
    Trace-Message "$LiteralPath[$Name]=$Value" -SkipFrames:3
}

[System.IO.StreamWriter] $Script:InstallLog = $null
Set-Variable -Name:'InstallPS1HKLM' -Value:'HKLM:\SOFTWARE\Microsoft\Microsoft Defender for Endpoint Install' -Option:Constant -Scope:Script

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
            }
            else {
                if ($null -eq (Get-Variable VMPosition -ErrorAction:Ignore)) {
                    $scriptFullName = '<interactive>'
                }
                else {
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

function Get-CurrentBootSession {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Get-CimInstance -ClassName:Win32_OperatingSystem).LastBootUpTime.ToString('yy/MM/ddTHH:mm:ss.fff')
}

function Exit-Install {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)] [string] $Message,
        [Parameter(Mandatory)] [uint32] $ExitCode)
    $fullMessage = Get-TraceMessage -Message:$Message
    if ($Script:ERR_PENDING_REBOOT -eq $ExitCode) {
        ## Subsequent runs of this scripts will be able to detect if a reboot happend since it was requested
        Set-RegistryKey -LiteralPath:$Script:InstallPS1HKLM -Name:'PendingReboot' -Value:$(Get-CurrentBootSession)
    }
    if ($null -ne $Script:InstallLog) {
        $Script:InstallLog.WriteLine($fullMessage)
        $exitMessage = Get-TraceMessage -Message ("Script will exit with code {0}(0x{0:x})" -f $ExitCode) -SkipFrames:1
        $Script:InstallLog.WriteLine($exitMessage)
        $Script:InstallLog.Close()
        $Script:InstallLog = $null
    }
    Write-Error $fullMessage -ErrorAction:Continue
    exit $ExitCode
}
function Trace-Message {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)] [string] $Message,
        [Parameter(Position = 1)][uint16] $SkipFrames = 2,
        [datetime] $Date = (Get-Date))
    $fullMessage = Get-TraceMessage -Message:$Message -SkipFrames:$SkipFrames -Date:$Date
    if ($null -ne $Script:InstallLog) {
        $Script:InstallLog.WriteLine($fullMessage)
    }
    Write-Host $fullMessage
}

function Trace-Warning {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string] $Message)
    $fullMessage = Get-TraceMessage "WARNING: $message"
    ## not using Write-Warning is intentional.
    if ($null -ne $Script:InstallLog) {
        $Script:InstallLog.WriteLine($fullMessage)
    }
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
    }
    catch {
        throw
    }
    finally {
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
        Minor    = '20230922'
        Patch    = '0'
        Metadata = 'A08BC943'
    }
    ## DO NOT EDIT THIS BLOCK - END
    [bool] $seen = $false
    $scriptLines = @(Get-Content -Path:$LiteralPath | ForEach-Object {
            $line = $_
            if (-not $seen) {            
                $seen = $line -ieq "#Copyright (C) Microsoft Corporation. All rights reserved."
                if ($line -match "^\s*Metadata\s*=\s*'([0-9A-F]{8})'") {
                    # skip it
                }
                else {
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
            }
            else {
                "Command `"$commandLine`" failed with error $exitCode after $runningTime"
            }
            Trace-Message $message -SkipFrames:$SkipFrames           
            if (-not $PassThru -and 0 -ne $exitCode) {
                exit $exitCode
            }
        } -ArgumentList:$ArgumentList, (2 + $SkipFrames)
    }
    catch {
        throw
    }
    finally {
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
    param([Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $File)
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
                }
                else {
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
        }
        catch {
            throw
        }
        finally {
            Invoke-Member $view 'Close'
            ReleaseComObject $view 
        }
    }
    
    try {
        $installer = New-Object -ComObject:WindowsInstaller.Installer        
        ## @see https://docs.microsoft.com/en-us/windows/win32/msi/database-object
        $database = Invoke-Member $installer 'OpenDatabase' ($MsiPath, 0)
        return Get-MsiFileTableHelper -Database:$database
    }
    catch {
        throw
    }
    finally {
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
            $_ -match 'add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+OnboardingInfo'
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
            $_ -match 'add\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"\s+\/v\s+696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A'
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
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $LiteralPath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $Name)

    ## @note: Get-ItemPropertyValue ... -ErrorAction:SilentlyContinue is complaining about errors.
    $k = Get-ItemProperty -LiteralPath:$LiteralPath -Name:$Name -ErrorAction:SilentlyContinue
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
            }
            catch {
                Trace-Warning "Error: $_"
            }
            finally {
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
            }
            else {
                Trace-Message "$reportingPath[$wppTracingLevel]=$wpp"
            }

            #Set-ItemProperty -LiteralPath:'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular' -Name:'TracingDisabled' -Value:0
            & logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile *>$null
            if (0 -eq $LASTEXITCODE) {
                Trace-Message "Tracing session '$logBase' started."
            }
            else {
                Trace-Warning "logman.exe create trace -n $logBase -pf $wdprov -ets -o $tempFile exited with exitcode $LASTEXITCODE"
            }
        }
        catch {
            throw
        }
        finally {
            Remove-Item -LiteralPath:$wdprov -ErrorAction:Continue
        }
    }
    return $etlParams
}

$currentDate = Get-Date
$Installps1LogName = "InstallPS1-$env:COMPUTERNAME.$($currentDate.ToString('yyMMddTHHmmssfffzzz').Replace(':', '')).log"
if (-not $NoMSILog.IsPresent -or -not $NoEtl.IsPresent) { 
    $InstallLogPath = Join-Path $PSScriptRoot -ChildPath:$Installps1LogName
    try {
        $Script:InstallLog = New-Object -TypeName:'System.IO.StreamWriter' -ArgumentList:@($InstallLogPath, $true)
        Trace-Message "$($PSCmdLet.MyInvocation.MyCommand.Name) traces will be saved to $InstallLogPath"
    } 
    catch {
        Trace-Warning "Error: $_"
    } 
}
Trace-Message "Running command: $(Get-CommandLine $PSCmdLet.MyInvocation)"

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
}
elseif (-not [System.Environment]::Is64BitProcess) {
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
            }
            else {
                $s
            }
        }
        foreach ($boundparam in $MyInvocation.BoundParameters.GetEnumerator()) {
            if ($boundparam.Value -is [switch]) {
                if ($boundparam.Value.ToBool()) {
                    $null = $argumentList.Add($("-{0}" -f $boundparam.Key))
                }
            }
            else {
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

if ($null -eq $ExtraWebRequestOptions) {
    $ExtraWebRequestOptions = @{}
}
else {
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
}
else {
    Join-Path -Path:$PSScriptRoot "md4ws.msi"
}

$action = if ($Uninstall.IsPresent) { 'uninstall' }  else { 'install' }
$logBase = "$action-$env:COMPUTERNAME"

if ($etl -or $log) {
    ## make sure $PSSCriptRoot is writable. 
    $tempFile = Join-Path -Path:$PSScriptRoot "$([guid]::NewGuid().Guid).tmp"
    Set-Content -LiteralPath:$tempFile -Value:'' -ErrorAction:SilentlyContinue
    if (-not (Test-Path -LiteralPath:$tempFile -PathType:Leaf)) {
        Exit-Install "Cannot create $tempFile. Is $PSScriptRoot writable?" -ExitCode:$ERR_DIRECTORY_NOT_WRITABLE
    }
    else {
        Remove-Item -LiteralPath:$tempFile -ErrorAction:SilentlyContinue
        $tempFile = $null
    }
}

$etlParams = @{}

try {
    $tempMsiLog = Join-Path -Path:$env:TEMP "$([guid]::NewGuid().Guid).log"
    [System.IO.FileStream] $msiStream = $null
    if ($action -eq 'install') {
        ## $msi should be checked as early as possible, see ICM#413339981
        if (-not (Test-Path -LiteralPath:$msi -PathType:leaf)) {
            Exit-Install "$msi does not exist. Please download latest $(Split-Path -Path:$msi -Leaf) into $PSScriptRoot and try again." -ExitCode:$ERR_MSI_NOT_FOUND
        }
        else {
            try {
                $msiStream = [System.IO.File]::OpenRead($msi)
                Trace-Message ("Handle {0} opened over {1}" -f $msiStream.SafeFileHandle.DangerousGetHandle(), $msi)
            }
            catch {
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
    }
    if ($null -ne $RemoveMMA) {
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
        $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
        if ($RemoveMMA -in $workspaces) {
            Trace-Message "Removing cloud workspace $($RemoveMMA.Guid)..." 
            $mma.RemoveCloudWorkspace($RemoveMMA)
            $workspaces = @($mma.GetCloudWorkspaces() | Select-Object -ExpandProperty:workspaceId)
            if ($workspaces.Count -gt 0) {
                $mma.ReloadConfiguration()
            }
            else {
                Stop-Service HealthService
            }
            Trace-Message "Workspace $($RemoveMMA.Guid) removed."
        }
        else {
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
    $lastBootTime = Get-CurrentBootSession
    Trace-Message "LastBootUpTime: $lastBootTime"
    Trace-Message "CurrentTime   : $($currentDate.ToString('yy/MM/ddTHH:mm:ss.fffzzz'))"
    $scriptPath = $MyInvocation.MyCommand.Path
    Trace-Message "$($MyInvocation.MyCommand.Name) version: $(Get-ScriptVersion -LiteralPath:$scriptPath)"

    $pendingReboot = Get-RegistryKey -LiteralPath:$Script:InstallPS1HKLM -Name:'PendingReboot'
    if ($pendingReboot -eq $lastBootTime) {        
        Trace-Warning "Previous run of $($PSCmdLet.MyInvocation.MyCommand.Name) requested a reboot"
        Exit-Install -Message:"Please restart this computer to continue $($PSCmdLet.MyInvocation.MyCommand.Name) actions" -ExitCode:$ERR_PENDING_REBOOT
    }
    elseif ($null -ne $pendingReboot) {
        Remove-ItemProperty -LiteralPath:$Script:InstallPS1HKLM -Name:'PendingReboot' -ErrorAction:SilentlyContinue
    }

    if ($action -eq 'install') {
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            $windefend = Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue
            $wdnissvc = Get-Service -Name:'WdNisSvc' -ErrorAction:SilentlyContinue
            $wdfilter = Get-Service -Name:'WdFilter' -ErrorAction:SilentlyContinue
            if ($windefend -and -not $wdnissvc -and -not $wdfilter) {
                ## workaround for ICM#278342470 (or VSO#37292177). Fixed on MOCAMP version 4.18.2111.150 or newer.
                if ($windefend.Status -eq 'Running') {
                    Exit-Install "Please reboot this computer to remove 'WinDefend' Service" -ExitCode:$ERR_PENDING_REBOOT
                }
                elseif ($windefend.Status -eq 'Stopped') {
                    $winDefendServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend'
                    if (Test-Path -LiteralPath:$winDefendServicePath) {
                        $imagePath = Get-RegistryKey -LiteralPath:$winDefendServicePath -Name:'ImagePath'
                        Trace-Message "WinDefend service is Stopped. ImagePath is $imagePath. Trying to remove $winDefendServicePath"
                        Remove-Item -LiteralPath:$winDefendServicePath -Force -Recurse -ErrorAction:SilentlyContinue
                        if (Test-Path -LiteralPath:$winDefendServicePath) {
                            Exit-Install "Cannot remove $winDefendServicePath" -ExitCode:$ERR_UNEXPECTED_STATE
                        }
                    }
                    else {
                        Trace-Warning "WinDefend service is stopped but $winDefendServicePath is gone. This usually happens when running this script more than once without restarting the machine."
                    }
                    Exit-Install "Please restart this machine to complete 'WinDefend' service removal" -ExitCode:$ERR_PENDING_REBOOT
                }
                else {
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
                }
                else {
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
                    }
                    elseif (0x80240017 -eq $exitCode) {
                        #0x80240017 = WU_E_NOT_APPLICABLE = Operation was not performed because there are no applicable updates.
                        Exit-Install -Message:"$KB not applicable, please follow the instructions from $link" -ExitCode:$ERR_INSUFFICIENT_REQUIREMENTS
                    }
                    elseif (0xbc2 -eq $exitCode) {
                        #0xbc2=0n3010,ERROR_SUCCESS_REBOOT_REQUIRED The requested operation is successful. Changes will not be effective until the system is rebooted
                        Exit-Install -Message "$KB required a reboot" -ExitCode:$ERR_PENDING_REBOOT
                    }
                    else {
                        Exit-Install -Message:"$KB installation failed with exitcode: $exitCode. Please follow the instructions from $link" -ExitCode:$exitCode
                    }
                }
                catch {
                    ## not ok to ignore, MSI will simply fail with generic error 1603.
                    throw
                }
                finally {
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
        }
        elseif ($osVersion.Major -eq 10 -and $osVersion.Minor -eq 0 -and $osVersion.Build -lt 18362) {
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
                        }
                        else {
                            Trace-Warning "$item not present"
                        }
                    }
                }
            }
            
            $windefendStatus = (Get-Service -Name:'WinDefend' -ErrorAction:SilentlyContinue).Status
            Trace-Message "'WindDefend' service status is '$windefendStatus'"
            $imageName = (Get-RegistryKey -LiteralPath:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''            
            if (0 -eq $imageName.Length) {
                Trace-Warning "'WinDefend' image path is null or empty. Still the '$($defenderFeature.FeatureName)' feature state is $($defenderFeature.State)"
                ## Workaround for ICM#423646508. In this scenario, "Restart is required by 'Windows-Defender'" error is ignored and this script is executed again without a restart.
                ## Windows-Defender optional feature is seen as 'Enabled' (but no services/files are present on the computer just yet) and previous versions of this script started
                ## to report issues unrelated with the issue at hand.
                Exit-Install "Restart is required by 'Windows-Defender'" -ExitCode:$ERR_PENDING_REBOOT
            }

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
                            }
                            catch {
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
                            }
                            else {
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
                }
                catch {
                    throw
                }
                finally {
                    $Global:ProgressPreference = $previousProgressPreference
                    if ($deleteUpdatePlatform) {
                        Remove-Item -LiteralPath:$updatePlatform -ErrorAction:SilentlyContinue
                        if (Test-Path -LiteralPath:$updatePlatform -PathType:Leaf) {
                            Trace-Warning "Could not delete $updatePlatform"
                        }
                        else {
                            Trace-Message "$updatePlatform deleted"
                        }
                    }
                }
            }
            else {
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
        }
        else {
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
        }
        else {
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
        }
        else {
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
        }
        catch {
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
                    }
                    else {
                        Trace-Warning "Running uninstall from System account - UninstallGUID is $uninstallGUID"
                    }
                }
                else {
                    Trace-Warning "Running uninstall from System account"
                }
            }

            $needWmiPrvSEMitigation = if ($null -ne $uninstallGUID) {
                $displayVersion = Get-RegistryKey -LiteralPath:"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${uninstallGUID}" -Name:'DisplayVersion'
                ## newer versions handle this via custom action inside the MSI
                $displayVersion -lt '4.18.60321'
            }
            else {
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
        if ($msi.Contains(' ')) { @('/i', "`"$msi`"") } else { @('/i', $msi) }
    }
    else {
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
    }
    else {
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
                    }
                    catch {
                        Trace-Warning "Failed to remove $itemPath"
                    }
                }
            }
        }

        if ($OnboardingScript.Length) {
            Trace-Message "Invoking onboarding script $OnboardingScript"
            $scriptPath = if ($OnboardingScript.Contains(' ') -and -not $OnboardingScript.StartsWith('"')) {
                '"{0}"' -f $OnboardingScript
            }
            else {
                $OnboardingScript
            }
            $argumentList = @('/c', $scriptPath)
            
            $exitCode = Measure-Process -FilePath:$((Get-Command 'cmd.exe').Path) -ArgumentList:$argumentList -PassThru
            if (0 -eq $exitCode) {
                Trace-Message "Onboarding successful."
            }
            else {
                Trace-Warning "Onboarding script returned $exitCode"
            }
        }
    }
}
catch {
    throw
}
finally {
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
            }
            else {
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
            }
            catch {
                Trace-Warning "Error: $_"
            }
            finally {
                if ($scheduledJob) {
                    Unregister-ScheduledJob -InputObject $scheduledJob -Force
                }
                if ($scheduledTask) {
                    Unregister-ScheduledTask -InputObject $scheduledTask -Confirm:$false
                }
            }

            Move-Item -LiteralPath:$tempFile -Destination:$etlLog -ErrorAction:Continue
            Trace-Message "$action.etl file: '$etlLog'."    
        }
    }
    else {
        Trace-Message "No $action.etl file generated."
    }

    if ($log -and (Test-Path -LiteralPath:$tempMsiLog -PathType:Leaf)) {
        Move-Item -LiteralPath:$tempMsiLog -Destination:$msiLog -ErrorAction:Continue
        Trace-Message "Msi $action.log: '$msiLog'"
    }
    else {
        Trace-Message "No $action.log file generated."
    }
    if ($null -ne $Script:InstallLog) {
        Trace-Message "$($PSCmdLet.MyInvocation.MyCommand.Name) traces: '$InstallLogPath'"
        $Script:InstallLog.Close()
        $Script:InstallLog = $null
    }
}
#Copyright (C) Microsoft Corporation. All rights reserved.

# SIG # Begin signature block
# MIImAgYJKoZIhvcNAQcCoIIl8zCCJe8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBwVAqNWhXAvUj/
# d6cgzqJbTWKnbP2gyAkrapZibzEaQaCCC1MwggTgMIIDyKADAgECAhMzAAAKdX3r
# GbkiXfErAAAAAAp1MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMDIxNjE5MDA0NloXDTI0MDEzMTE5MDA0NlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm8WsyPSBF
# EhzxVlIBXzf7oJ80Ie8UY2fgPE40Efe97fn7mMo3Pyr4zWv4B3mG5tfMta6fULwC
# 4FuNpgEHBntPXOpyCHpJXYIggff2YOllKtdP4jPi0kueDvim/+uhBVHVvQTJfuG1
# HhG6tAQ9Ts2+QtrMMUyvLuRT1Mt6dANp9XJ2dlshPAR0IMyvVr/B5UxrvsBBjGd9
# nwVJdGaMOEcX4GY1JS0WV+md+vKTeZBh+kAl8Vc21p2FkTqmgqlBSALAhZvWgisa
# RSRIQc330EKeTuqM8Isrpn+5sQ8khBzAaimOFtYu1DvnY0q2ZvCCcIcr3T39uyq1
# 4N88zal30wCtAgMBAAGjggFoMIIBZDAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUviUXPislHupG6qw+6BLkdAIZjgowRQYDVR0RBD4w
# PKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMN
# MjMwMDI4KzUwMDE4OTAfBgNVHSMEGDAWgBTRT6mKBwjO9CQYmOUA//PWeR03vDBT
# BgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5jcmwwVwYIKwYBBQUHAQEE
# SzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4IBAQBX8cmfh/BkgIZ0YrvNBGc0eniJX+zamIxh08ELJtiKcmhA
# jiBOq6AU7PAT9bZq+zYSoyIkSV4K3YpYy6T4qZ755rbjPuh87Yjb/boFg5BL3SDH
# 0KQ/6Su2khM2T+HicYWro0JsiPGwPv/GFOMRGvQN0tf2IiYV+BedAM2TmNF2f6LS
# jX24PO6O81VcqJD13Qj0UlGG6OezTI/P9lxupc2MVxTullLlGXwjN2cP2rgGKZiE
# qQrCiO6/Y7hqEdNvhKrs9NnDo9PGbDWUMN4DwKGwJZFRySG+KogcZkk7ozOvM6p9
# +TLQS+3TmlFJlmRHtf7Fjma2sWc3mhyz17drnj05MIIGazCCBFOgAwIBAgIKYQxq
# GQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIzWhcNMjUwNzA2MjA1MDIz
# WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQD
# ExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+DZ0U5LGfwciUsDh8H9Az
# VfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdScFosHZSrGb+vlX2vZqFv
# m2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/OEbmisdzaXZVaZZM5Njw
# NOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMUpUwIoIPXIx/zX99vLM/a
# FtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jAvguTHijgc23SVOkoTL9r
# XZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEAAaOCAeMwggHfMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQYmOUA//PWeR03vDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
# AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Q
# S0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcA
# YQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
# hvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnClHDDZJTD2FamkI7+5Jr0
# bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz/Q2QJCTj+dyWyvy4rL/0
# wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0bjPMAYkG6SHSHgv1QyfSH
# KcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9TUj3bkFHUhy7G8JXOqiZ
# VpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b3CLVFCNqQX/QQqbb7yV7
# BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9pE/oGw5rduS4j7DC6v11
# 9yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6MjugagwI7RiE+TIPJwX9hr
# cqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpolVf1Ayq1kEOgx+RJUeRry
# DtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ239Q+J9iguymghZ8Zrzs
# mbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcNGw186/RayZXPhxIKXezF
# ApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w3gI/h+5WoezrtUyFMYIa
# BTCCGgECAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENBIDIwMTACEzMAAAp1fesZ
# uSJd8SsAAAAACnUwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIDsP1c+xd72zSIjVjsQh7Uj7r4fKfiUr65lPh/w/dIqXMEIGCisGAQQB
# gjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAfzTdUS1KvioHlif94zfOGZZe
# YujEpc7Orvaczn9MAdPdYDFCaC8XGjo5rADLDYyuBT8LxzEWHS8iuc8YkTP0QmTQ
# HgzoedV/oedgNhfA9/JuPZVWLETazpoRdC4bPn+LzlGiXoZ730FGh5vPmykFmvgw
# 0RqUCHnhYP3UBLT15CFbZRuGpcS2CrNFHps2qeo/FNHozuFOimpKpx/ezfZLPbve
# +Rl0ebIsI/7zAoz1XsFFnsQYnh4SQ/HauuVBiROc30hvfkRjSwAQtPcrAfvFXDAz
# ZPbjxJYzx46rLL3iZunL92YzL3xPdXemx0cM8lwFbTLUtJDbRBJTQFTqiTWhwaGC
# F5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20wghdpAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCD6NQzDnW4OFbPaEF6NHEP8
# Lkw1d2OWU9dTPXgOx0QSFQIGZQPuZVLuGBMyMDIzMDkyNjA5NDMyOS4yMjNaMASA
# AgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQL
# Ex5uU2hpZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgITMwAAAdB3
# CKrvoxfG3QABAAAB0DANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDAeFw0yMzA1MjUxOTEyMTRaFw0yNDAyMDExOTEyMTRaMIHLMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBF
# U046QTAwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDfMlfn35fv
# M0XAUSmI5qiG0UxPi25HkSyBgzk3zpYO311d1OEEFz0QpAK23s1dJFrjB5gD+SMw
# 5z6EwxC4CrXU9KaQ4WNHqHrhWftpgo3MkJex9frmO9MldUfjUG56sIW6YVF6YjX+
# 9rT1JDdCDHbo5nZiasMigGKawGb2HqD7/kjRR67RvVh7Q4natAVu46Zf5MLviR0x
# N5cNG20xwBwgttaYEk5XlULaBH5OnXz2eWoIx+SjDO7Bt5BuABWY8SvmRQfByT2c
# ppEzTjt/fs0xp4B1cAHVDwlGwZuv9Rfc3nddxgFrKA8MWHbJF0+aWUUYIBR8Fy2g
# uFVHoHeOze7IsbyvRrax//83gYqo8c5Z/1/u7kjLcTgipiyZ8XERsLEECJ5ox1BB
# LY6AjmbgAzDdNl2Leej+qIbdBr/SUvKEC+Xw4xjFMOTUVWKWemt2khwndUfBNR7N
# zu1z9L0Wv7TAY/v+v6pNhAeohPMCFJc+ak6uMD8TKSzWFjw5aADkmD9mGuC86yvS
# KkII4MayzoUdseT0nfk8Y0fPjtdw2Wnejl6zLHuYXwcDau2O1DMuoiedNVjTF37U
# EmYT+oxC/OFXUGPDEQt9tzgbR9g8HLtUfEeWOsOED5xgb5rwyfvIss7H/cdHFcIi
# IczzQgYnsLyEGepoZDkKhSMR5eCB6Kcv/QIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FDPhAYWS0oA+lOtITfjJtyl0knRRMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCX
# h+ckCkZaA06SNW+qxtS9gHQp4x7G+gdikngKItEr8otkXIrmWPYrarRWBlY91lqG
# iilHyIlZ3iNBUbaNEmaKAGMZ5YcS7IZUKPaq1jU0msyl+8og0t9C/Z26+atx3vsh
# HrFQuSgwTHZVpzv7k8CYnBYoxdhI1uGhqH595mqLvtMsxEN/1so7U+b3U6LCry5u
# wwcz5+j8Oj0GUX3b+iZg+As0xTN6T0Qa8BNec/LwcyqYNEaMkW2VAKrmhvWH8OCD
# TcXgONnnABQHBfXK/fLAbHFGS1XNOtr62/iaHBGAkrCGl6Bi8Pfws6fs+w+sE9r3
# hX9Vg0gsRMoHRuMaiXsrGmGsuYnLn3AwTguMatw9R8U5vJtWSlu1CFO5P0LEvQQi
# MZ12sQSsQAkNDTs9rTjVNjjIUgoZ6XPMxlcPIDcjxw8bfeb4y4wAxM2RRoWcxpkx
# +6IIf2L+b7gLHtBxXCWJ5bMW7WwUC2LltburUwBv0SgjpDtbEqw/uDgWBerCT+Zt
# y3Nc967iGaQjyYQH6H/h9Xc8smm2n6VjySRx2swnW3hr6Qx63U/xY9HL6FNhrGiF
# ED7ZRKrnwvvXvMVQUIEkB7GUEeN6heY8gHLt0jLV3yzDiQA8R8p5YGgGAVt9MEwg
# AJNY1iHvH/8vzhJSZFNkH8svRztO/i3TvKrjb8ZxwjCCB3EwggVZoAMCAQICEzMA
# AAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMw
# MDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
# nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
# jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
# fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+
# jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c
# +gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+
# cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C6
# 26p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV
# 2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoS
# CtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxS
# UV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJp
# xq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
# BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
# KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9S
# ZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwEx
# JFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
# 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
# dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
# EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMu
# LGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT9
# 9kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2z
# AVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6Ile
# T53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6l
# MVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbh
# IurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3u
# gm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCByzELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
# b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OkEwMDAtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQC8t8hT8KKUX91lU5FqRP9Cfu9MiaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUA
# AgUA6LzsNzAiGA8yMDIzMDkyNjA1MzU1MVoYDzIwMjMwOTI3MDUzNTUxWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDovOw3AgEAMAcCAQACAhwuMAcCAQACAhJRMAoC
# BQDovj23AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAKJZSL3C95VbCUdn
# 1Tk73BshM7Qd65nicbSbHFyamqbBhot4ncIq7QxvErw1+VgDUIcCf6rdY97SGm3S
# tudj8jnF3GCcKIn7R8nAIhfaWCyszW+rGwgzyIbKBXG4miElkX/cqN+0GVPn5vF8
# GQGc7CrRJkhk2HOuVEcU7Fgb2xsqeVHinz5K1HSxMV6gr/6frwoeDNkIobSdPmrc
# xKx8z4m7XqO5Tjqe1eA74og5lZ+oINP/XNqHkMRnofQ44Cu4MutR/IYzuKL7mHIs
# CnuR3qzN9AqTcaEkeqKPJt8ioB8Q20KnlBnG5C/lRhad8ycAGIYu4eirdUUTTI4r
# zh4E2I4xggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAdB3CKrvoxfG3QABAAAB0DANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBscZUELJXBWGxQ
# FRkuLfriXrsNGr+D8ckUAhbp6rvqnzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIAiVQAZftNP/Md1E2Yw+fBXa9w6fjmTZ5WAerrTSPwnXMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHQdwiq76MXxt0AAQAAAdAw
# IgQgcy78gIOxBpfyCJJFAnmoBpWDfxiczqgQjTaprde+St4wDQYJKoZIhvcNAQEL
# BQAEggIAprBjwOqJqvTLclD2Y3C+Z6C+MBOuh/o8mIOXxsDEPdORFB0ubgIiXDuI
# AuaV3TL7pKHa9p8eY9btr9vdD4+h5rPIc29Bo2KpAa8wJ3BfJtLZ+FydTcocGAVN
# NBhcZ/2sDbHv2pT/VfZ0MkNMfibCfZwUu+K4w3Io08HlbInLhQhRIzTjW9pXuM1q
# QwLCN3x7VZFuggYwXR2xnKg87S3nLDje8bKn/CHbesna8wnD+AhAm094r75ya0tr
# 86MmfM/q3SnMSWu+ssbiyMQKiqT6HbtEan9vi/2ABf3TheXMszlKxeC/K//Igdgl
# 63+xPZqo667+RmARvz4on1MBE61+iRjGfFS0am9doxyvlsYyBHXNsdnjDbvRdvOk
# Kd3DSdmxmCqdW37VsVV63US9Zlr4i4XNfd+uB3tFXVjNE0GKw5jfOpqUQR32oqy5
# tMn4F2gc8YtDvPgc+Qyaj1iwZ98Y5FmV90zDINJ5T1MIslsCmixqHcBjWUQOzBvD
# lI+SW8QfOnOODKk2rHeYbGCxF9UOEZ9YKjlkpLsruUc6YdvficETSjvJYbqKhPFg
# NuYBqlN8QITqn0HAx2lXYAg84UeA5wKvWXtoPsjZfFYNZo2zYuR40Ule1Fj9JArx
# vDfbkBn6cCZwzOC4aoX5h1d50gHH4C/gJuj0QBpDVg2RlmpszQY=
# SIG # End signature block
