# Foreground-only viewer. The detached worker keeps writing durable log/state files.
function Watch-PntOperation {
    param([string]$Directory,[string]$Operation,[Diagnostics.Process]$Process)
    $esc=[char]27;$terminal=-not [Console]::IsOutputRedirected -and $env:TERM -ne 'dumb'
    $readers=@{};$stage='Preparing';$percent=0;$lastStage=''
    function Read-PntLogs {
        foreach($extension in @('log','err')){
            $path=Join-Path $Directory "$Operation.$extension"
            if(-not $readers.ContainsKey($extension) -and [IO.File]::Exists($path)){
                $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]'ReadWrite,Delete')
                $readers[$extension]=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true)
            }
            if($readers.ContainsKey($extension)){
                $text=$readers[$extension].ReadToEnd()
                if($text){[Console]::Write([regex]::Replace($text,'\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1B]*(?:\x07|\x1B\\))',''))}
            }
        }
    }
    try{
        if($terminal){
            # Enable VT processing on classic Windows consoles as well as Windows Terminal.
            if(-not ('PntOperationConsole' -as [type])){Add-Type 'using System;using System.Runtime.InteropServices;public static class PntOperationConsole{[DllImport("kernel32.dll")]public static extern IntPtr GetStdHandle(int n);[DllImport("kernel32.dll")]public static extern bool GetConsoleMode(IntPtr h,out uint m);[DllImport("kernel32.dll")]public static extern bool SetConsoleMode(IntPtr h,uint m);}' }
            $handle=[PntOperationConsole]::GetStdHandle(-11);[uint32]$oldMode=0
            if([PntOperationConsole]::GetConsoleMode($handle,[ref]$oldMode)){$modeChanged=[PntOperationConsole]::SetConsoleMode($handle,$oldMode -bor 4)}
            [Console]::Write("$esc[?1049h$esc[?25l$esc[2J$esc[H")
        }
        while($true){
            Read-PntLogs
            $state=Join-Path $Directory "$Operation.stage"
            if([IO.File]::Exists($state)){
                try{$lines=[IO.File]::ReadAllLines($state,[Text.Encoding]::UTF8);if($lines.Length -ge 2){$percent=[Math]::Min(100,[Math]::Max(0,[int]$lines[0]));$stage=$lines[1]}}catch [IO.IOException]{}
            }
            if($terminal){
                $height=[Math]::Max(5,[Console]::WindowHeight);$width=[Math]::Max(10,[Console]::WindowWidth)
                $label=[regex]::Replace($stage,'[\x00-\x1f\x7f]',' ');if($label.Length -ge $width){$label=$label.Substring(0,$width-1)}
                $barWidth=[Math]::Min(20,[Math]::Max(1,$width-10));$filled=[int][Math]::Floor($percent*$barWidth/100);$bar=('#'*$filled)+('-'*($barWidth-$filled))
                [Console]::Write("$esc"+'7'+"$esc[1;$($height-2)r$esc[$($height-1);1H$esc[2K[$bar] $percent%$esc[$height;1H$esc[2K$label$esc"+'8')
            }elseif($stage -ne $lastStage){[Console]::WriteLine("--- $stage ---");$lastStage=$stage}
            $result=Join-Path $Directory "$Operation.result"
            if([IO.File]::Exists($result)){
                $Process.WaitForExit();Read-PntLogs
                return [int]([IO.File]::ReadAllText($result))
            }
            if($Process.HasExited){Read-PntLogs;throw 'Background worker exited without a result.'}
            Start-Sleep -Milliseconds 200
        }
    }finally{
        foreach($reader in $readers.Values){$reader.Dispose()}
        if($terminal){[Console]::Write("$esc[r$esc[?25h$esc[?1049l");if($modeChanged){[PntOperationConsole]::SetConsoleMode($handle,$oldMode) | Out-Null}}
        [Console]::WriteLine('Log: '+(Join-Path $Directory "$Operation.log"))
    }
}
