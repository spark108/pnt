$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../deploy/pnt.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer syntax errors.'}
$handoff=$ast.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.StartsWith('if($Action -eq ''update'' -and -not $SourcesReady)')},$true) | Select-Object -First 1
if(-not $handoff){throw 'Update handoff not found.'}
foreach($mode in @('success','pull-failed','child-failed')){
    $workspace=Join-Path ([IO.Path]::GetTempPath()) ('pnt-handoff-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $workspace 'source/deploy') -Force | Out-Null
    $fresh=@'
param($Action,[switch]$Worker,$Operation,$EventId,[switch]$SourcesReady,[IO.FileStream]$UpdateLock)
$root=$env:PNT_HANDOFF_TEST_ROOT
if(-not $SourcesReady -or -not $Worker -or $Action -ne 'update' -or $EventId -ne ('a'*32) -or $Operation -ne ('b'*32)){throw 'Handoff arguments lost.'}
if(-not $UpdateLock -or -not $UpdateLock.CanWrite){throw 'Update lock was not transferred.'}
try{
    $second=[IO.File]::Open($UpdateLock.Name,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $second.Dispose();throw 'Update lock was released during handoff.'
}catch [IO.IOException]{}
[IO.File]::WriteAllText((Join-Path $root 'new-worker'),'executed')
$code=if($env:PNT_HANDOFF_TEST_MODE -eq 'child-failed'){'1'}else{'0'}
[IO.File]::WriteAllText((Join-Path $root 'result'),$code)
if($code -eq '1'){exit 1}
'@
    [IO.File]::WriteAllText((Join-Path $workspace 'incoming.ps1'),$fresh)
    [IO.File]::WriteAllText((Join-Path $workspace 'source/deploy/pnt.ps1'),'throw "Old worker executed"')
    $prelude=@'
$ErrorActionPreference='Stop'
$root=$env:PNT_HANDOFF_TEST_ROOT
$source=Join-Path $root 'source';$result=Join-Path $root 'result'
$Action='update';$SourcesReady=$false;$Operation='b'*32;$EventId='a'*32;$repository='test-repository'
$lock=[IO.File]::Open((Join-Path $root 'maintenance.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$success=$false
function git {
    if($args -contains 'symbolic-ref'){$global:LASTEXITCODE=0;return 'master'}
    if($args -contains 'pull'){
        if($env:PNT_HANDOFF_TEST_MODE -eq 'pull-failed'){$global:LASTEXITCODE=42;return}
        Copy-Item -LiteralPath (Join-Path $root 'incoming.ps1') -Destination (Join-Path $source 'deploy/pnt.ps1')
    }
    $global:LASTEXITCODE=0
}
function Native($File,$Arguments){& $File @Arguments;if($LASTEXITCODE -ne 0){throw 'Git failed.'}}
function Stage($Message){}
function Begin-Stage($Message,$Percent){}
try{
'@
    $ending=@'
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}
finally{
    $lock.Dispose()
    [IO.File]::WriteAllText($result,$(if($success){'0'}else{'1'}))
}
'@
    $runner=Join-Path $workspace 'runner.ps1'
    [IO.File]::WriteAllText($runner,$prelude+"`n"+$handoff.Extent.Text+"`n"+$ending)
    $env:PNT_HANDOFF_TEST_ROOT=$workspace;$env:PNT_HANDOFF_TEST_MODE=$mode
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner
    $expected=if($mode -eq 'success'){'0'}else{'1'}
    if([IO.File]::ReadAllText((Join-Path $workspace 'result')) -ne $expected){throw "Incorrect result for $mode"}
    $executed=Test-Path (Join-Path $workspace 'new-worker')
    if($executed -ne ($mode -ne 'pull-failed')){throw "Incorrect worker execution for $mode"}
}
Remove-Item Env:PNT_HANDOFF_TEST_ROOT,Env:PNT_HANDOFF_TEST_MODE
Write-Output 'PASS: fresh Windows worker, preserved lock and event, failed pull, child result propagation.'
