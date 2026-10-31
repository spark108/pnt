param(
    [ValidateSet('install','update','repair','start','stop','restart','status')][string]$Action='status',
    [switch]$Worker,
    [string]$Operation,
    [string]$EventId,
    [switch]$SourcesReady,
    [IO.FileStream]$UpdateLock
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$OutputEncoding=[Console]::OutputEncoding
$env:DOTNET_CLI_UI_LANGUAGE='en'
$root=Join-Path $env:ProgramData 'PNT'
$app=Join-Path $root 'app'
$config=Join-Path $root 'config'
$sourceFile=Join-Path $config 'source-dir'
$source=Split-Path $PSScriptRoot -Parent
if(Test-Path $sourceFile){$source=[IO.File]::ReadAllText($sourceFile).Trim()}
$exe=Join-Path $app 'pnt.exe'
$repository='https://github.com/spark108/pnt.git'
function Native([string]$File,[string[]]$Arguments){
    # Windows PowerShell treats native stderr as ErrorRecord, even for successful Git commands.
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';& $File @Arguments 2>&1 | ForEach-Object {[Console]::Out.WriteLine($_.ToString())};$code=$LASTEXITCODE}
    finally{$ErrorActionPreference=$previous}
    if($code -ne 0){throw "$File failed with exit code $code"}
}
function Cluster-Available {
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';& $exe node status --require-cluster *> $null;return ($LASTEXITCODE -eq 0)}
    finally{$ErrorActionPreference=$previous}
}
function Begin-Stage([string]$Message,[int]$Percent){
    [IO.File]::WriteAllText($state,"$Percent`n$Message`n",[Text.UTF8Encoding]::new($false))
    Write-Output ("--- $Message ---")
}
function Stage([string]$Message){Write-Output ("OK: $Message");[IO.File]::AppendAllText($progress,"✓ $Message`n",[Text.UTF8Encoding]::new($false))}
function Ensure-Git([string]$Workspace){
    if(Get-Command git -ErrorAction SilentlyContinue){return}
    $release=Invoke-RestMethod 'https://api.github.com/repos/git-for-windows/git/releases/latest'
    $asset=$release.assets | Where-Object name -Match '^MinGit-.*-64-bit.zip$' | Select-Object -First 1
    if(-not $asset){throw 'Cannot find MinGit x64 asset.'}
    $archive=Join-Path $Workspace 'git.zip';Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile $archive
    Expand-Archive $archive -DestinationPath (Join-Path $tools 'git') -Force
}
function Move-Managed([string]$From,[string]$To){
    $base=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
    $fromPath=[IO.Path]::GetFullPath($From);$toPath=[IO.Path]::GetFullPath($To)
    if(-not $fromPath.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or -not $toPath.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing move outside PNT directories.'}
    Move-Item -LiteralPath $fromPath -Destination $toPath
}
function Remove-Managed([string]$Path){
    if(-not $Path -or -not (Test-Path -LiteralPath $Path)){return}
    $resolved=[IO.Path]::GetFullPath($Path);$base=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
    $name=Split-Path $resolved -Leaf
    if(-not $resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or ($name -notlike 'build-*' -and $name -notlike 'app-backup-*')){throw 'Refusing cleanup outside PNT build/backup directories.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
}
try {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $authorized=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(-not $authorized){
        try{$groupSid=([Security.Principal.NTAccount]::new([Environment]::MachineName,'PNTAdmin')).Translate([Security.Principal.SecurityIdentifier]);$authorized=$principal.IsInRole($groupSid)}catch{}
    }
    if(-not $authorized){throw 'Only Administrator or members of PNTAdmin may use PNT.'}
    if($Action -eq 'status'){
        $service=Get-Service PNT -ErrorAction SilentlyContinue
        if($service){$service | Format-Table Name,Status,StartType}else{Write-Output 'PNT service is not installed.'}
        $recent=Get-ChildItem (Join-Path $root 'operations') -Filter '*.progress' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if($recent){Get-Content -LiteralPath $recent.FullName -Encoding UTF8};exit 0
    }
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from an Administrator terminal.'}
    . (Join-Path $PSScriptRoot 'access.ps1')
    if($Action -eq 'repair'){
        Repair-PntAccess -DataPath (Join-Path $root 'data')
        Write-Output 'PNT data permissions repaired. Database and certificates preserved. Run pnt.bat update next.'
        exit 0
    }
    if($Action -in @('start','stop','restart')){
        switch($Action){start{Start-Service PNT}stop{Stop-Service PNT}restart{Restart-Service PNT}};exit 0
    }
    $operations=Join-Path $root 'operations';New-Item -ItemType Directory -Force $operations | Out-Null
    if(-not $Worker){
        $Operation=[guid]::NewGuid().ToString('N')
        $arguments="-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action $Action -Worker -Operation $Operation"
        if($EventId){if($EventId -notmatch '^[0-9a-fA-F]{32}$'){throw 'Invalid update event'};$arguments+=" -EventId $EventId"}
        $child=Start-Process powershell.exe -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $operations "$Operation.log") -RedirectStandardError (Join-Path $operations "$Operation.err")
        Write-Output "Background operation: $Action"
        . (Join-Path $PSScriptRoot 'operation-ui.ps1')
        $code=Watch-PntOperation -Directory $operations -Operation $Operation -Process $child
        Write-Output ("PNT operation result: $code")
        exit $code
    }
    if($Operation -notmatch '^[0-9a-fA-F]{32}$'){throw 'Invalid operation ID'}
    $progress=Join-Path $operations "$Operation.progress";$result=Join-Path $operations "$Operation.result"
    $state=Join-Path $operations "$Operation.stage"
    $lock=$null;$temp=$null;$backup=$null;$stopped=$false;$maintenance=$false;$success=$false;$createdService=$false;$installedApp=$false
    try{
        if($SourcesReady){
            if($Action -ne 'update' -or -not $UpdateLock -or $UpdateLock.Name -ne (Join-Path $root 'maintenance.lock')){throw 'Invalid update handoff.'}
            $lock=$UpdateLock
        }else{$lock=[IO.File]::Open((Join-Path $root 'maintenance.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
        if($Action -eq 'install' -and (Test-Path $exe)){throw 'PNT is installed; use update.'}
        if($Action -eq 'update' -and -not (Test-Path $exe)){throw 'Install PNT first.'}
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $tools=Join-Path $root 'tools';New-Item -ItemType Directory -Force $tools | Out-Null
        $env:PATH=(Join-Path $tools 'git\cmd')+';'+(Join-Path $tools 'dotnet')+';'+$env:PATH
        $temp=Join-Path $root ('build-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $temp | Out-Null
        if(-not $SourcesReady){Begin-Stage 'Preparing Git' 0}
        Ensure-Git $temp
        if($Action -eq 'update' -and -not $SourcesReady){
            Begin-Stage 'Updating sources from GitHub' 5
            Native git -Arguments @('-C',$source,'remote','set-url','origin',$repository)
            $branch=& git -C $source symbolic-ref --short HEAD;if($LASTEXITCODE -ne 0){throw 'A source branch is required.'}
            $env:GIT_TERMINAL_PROMPT='0';Native git -Arguments @('-C',$source,'pull','--ff-only','origin',$branch);Stage 'Sources updated from GitHub'
            & (Join-Path $source 'deploy\pnt.ps1') -Action update -Worker -Operation $Operation -EventId $EventId -SourcesReady -UpdateLock $lock
            if(-not (Test-Path $result)){throw 'Updated worker exited without a result.'}
            $code=[int]([IO.File]::ReadAllText($result));$success=($code -eq 0);exit $code
        }
        if($Action -eq 'update'){
            Begin-Stage 'Repairing data permissions' 15
            Repair-PntAccess -DataPath (Join-Path $root 'data');Stage 'Data permissions repaired'
            if(Cluster-Available){
                Begin-Stage 'Announcing maintenance' 20
                try{Native $exe -Arguments @('node','maintenance','start');$maintenance=$true;Stage 'Update status announced';Start-Sleep 8}
                catch{Write-Output ('Update announcement unavailable: '+$_.Exception.Message)}
            }
            Begin-Stage 'Stopping Windows service' 25
            $service=Get-Service PNT -ErrorAction SilentlyContinue
            if($service -and $service.Status -ne 'Stopped'){Stop-Service PNT -ErrorAction Stop}
            $stopped=[bool]$service;Stage 'Service stopped'
        }
        Begin-Stage 'Installing Git and .NET dependencies' 30
        $sdks=if(Get-Command dotnet -ErrorAction SilentlyContinue){& dotnet --list-sdks}else{''}
        if(-not ($sdks | Select-String '^10\.')){
            $installer=Join-Path $temp 'dotnet-install.ps1';Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer
            & $installer -Channel '10.0' -InstallDir (Join-Path $tools 'dotnet') -NoPath
            if(-not ((& dotnet --list-sdks) | Select-String '^10\.')){throw '.NET 10 SDK installation failed.'}
        }
        Stage 'Git and .NET dependencies ready'
        if($Action -eq 'install' -and -not (Test-Path (Join-Path $source '.git'))){
            Begin-Stage 'Cloning sources from GitHub' 45
            $source=Join-Path $root 'source'
            if(-not (Test-Path $source)){Native git -Arguments @('clone',$repository,$source)}
            elseif(-not (Test-Path (Join-Path $source '.git'))){throw 'The PNT source directory exists but is not a Git checkout.'}
        }
        if(-not (Test-Path (Join-Path $source 'pnt.csproj'))){throw 'Run install from the source checkout.'}
        $rid=if($env:PROCESSOR_ARCHITECTURE -eq 'ARM64'){'win-arm64'}else{'win-x64'}
        Begin-Stage 'Building PNT' 55
        $build=Join-Path $temp 'publish';Native dotnet -Arguments @('publish',(Join-Path $source 'pnt.csproj'),'-c','Release','-r',$rid,'--self-contained','true','-p:PublishSingleFile=true','-o',$build);Stage 'Binary built'
        Begin-Stage 'Installing binary and configuring permissions' 80
        $data=Join-Path $root 'data';New-Item -ItemType Directory -Force $data,$config,(Join-Path $root 'bin') | Out-Null
        Repair-PntAccess -DataPath $data
        if(Test-Path $app){$backup=Join-Path $root ('app-backup-'+$Operation);Move-Managed $app $backup}
        Move-Managed $build $app;$installedApp=$true
        Native $exe -Arguments @('_prepare-access')
        [IO.File]::WriteAllText($sourceFile,$source)
        [IO.File]::WriteAllText((Join-Path $root 'bin\pnt.cmd'),"@echo off`r`n`"$exe`" %*`r`n",[Text.Encoding]::ASCII)
        $bin=Join-Path $root 'bin';$machinePath=[Environment]::GetEnvironmentVariable('PATH','Machine')
        if(($machinePath -split ';') -notcontains $bin){[Environment]::SetEnvironmentVariable('PATH',($machinePath+';'+$bin),'Machine')}
        if(-not (Get-Service PNT -ErrorAction SilentlyContinue)){New-Service -Name PNT -DisplayName 'PNT cluster node' -BinaryPathName ('"'+$exe+'" serve') -StartupType Automatic | Out-Null;$createdService=$true}
        Set-Service PNT -StartupType Automatic
        Native sc.exe -Arguments @('failure','PNT','reset=','86400','actions=','restart/5000/restart/10000/restart/30000')
        Begin-Stage 'Starting Windows service' 95
        Start-Service PNT;Start-Sleep 2;if((Get-Service PNT).Status -ne 'Running'){throw 'Service failed to start.'};Stage 'Windows service started; pnt added to system PATH'
        if($maintenance){Native $exe -Arguments @('node','maintenance','done');$maintenance=$false}
        if($Action -eq 'update'){
            if($EventId){Native $exe -Arguments @('node','update','applied',$EventId)}else{
                if(Cluster-Available){$commit=& git -C $source rev-parse HEAD;Native $exe -Arguments @('node','update','announce',$commit)}
            }
        }
        $success=$true;Begin-Stage 'Operation completed' 100;Stage 'Operation completed'
    }finally{
        if(-not $success){
            if($createdService){Stop-Service PNT -ErrorAction SilentlyContinue;& sc.exe delete PNT | Out-Null}
            if($backup -and (Test-Path $backup)){
                Stop-Service PNT -ErrorAction SilentlyContinue
                if(Test-Path $app){$failed=Join-Path $root ('app-failed-'+$Operation);Move-Managed $app $failed}
                Move-Managed $backup $app
            }
            elseif($Action -eq 'install' -and $installedApp -and (Test-Path $app)){Move-Managed $app (Join-Path $root ('app-failed-'+$Operation))}
            if($stopped){Start-Service PNT -ErrorAction SilentlyContinue}
            if($maintenance -and (Test-Path $exe)){try{Native $exe -Arguments @('node','maintenance','done')}catch{Write-Output $_.Exception.Message}}
        }
        if($lock){$lock.Dispose()}
        Remove-Managed $temp
        if($success){Remove-Managed $backup}
        [IO.File]::WriteAllText($result,$(if($success){'0'}else{'1'}))
    }
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}
