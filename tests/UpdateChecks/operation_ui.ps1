$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../deploy/operation-ui.ps1')
$folder=Join-Path ([IO.Path]::GetTempPath()) ('pnt-ui-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($folder) | Out-Null
$worker=Join-Path $folder 'worker.ps1'
[IO.File]::WriteAllText($worker,@'
param($Folder)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $Folder 'test.stage'),"10`nInstalling packages`n")
[Console]::WriteLine('package download live')
[Console]::Out.Flush();Start-Sleep -Milliseconds 500
[IO.File]::WriteAllText((Join-Path $Folder 'test.stage'),"55`nBuilding PNT`n")
[Console]::WriteLine('compiler log live');[Console]::Error.WriteLine('diagnostic stderr')
[Console]::Out.Flush();Start-Sleep -Milliseconds 500
[IO.File]::WriteAllText((Join-Path $Folder 'test.result'),'7')
'@)
$child=Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -File `"$worker`" -Folder `"$folder`"" -PassThru -RedirectStandardOutput (Join-Path $folder 'test.log') -RedirectStandardError (Join-Path $folder 'test.err')
$original=[Console]::Out;$capture=[IO.StringWriter]::new()
try{[Console]::SetOut($capture);$code=Watch-PntOperation -Directory $folder -Operation test -Process $child}
finally{[Console]::SetOut($original)}
$text=$capture.ToString()
if($code -ne 7 -or -not $text.Contains('package download live') -or -not $text.Contains('compiler log live') -or -not $text.Contains('diagnostic stderr') -or $text.Contains([char]27)){throw 'Plain viewer lost logs, result, or emitted terminal escapes.'}
foreach($path in @('deploy/pnt.ps1','deploy/operation-ui.ps1')){
    $tokens=$null;$errors=$null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot "../../$path"),[ref]$tokens,[ref]$errors) | Out-Null
    if($errors.Count){throw ($errors | Out-String)}
}
Write-Output 'PASS: live stdout/stderr, stage files, redirected plain output, exit code and Windows script syntax.'
