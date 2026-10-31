# This file only defines repair functions; dot-sourcing it does not change the system.
function Set-PntDirectoryAcl {
    param([Parameter(Mandatory=$true)][string]$DataPath,
          [Parameter(Mandatory=$true)][Security.Principal.SecurityIdentifier]$GroupSid,
          [Security.Principal.SecurityIdentifier]$AdministratorSid='S-1-5-32-544')
    $directory=[IO.Path]::GetFullPath($DataPath)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    if(([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'The PNT data directory must not be a reparse point.'}
    function Test-PntMissingItem($Failure){
        $exception=$Failure.Exception
        while($exception){
            if($exception -is [IO.FileNotFoundException] -or $exception -is [IO.DirectoryNotFoundException] -or $exception -is [Management.Automation.ItemNotFoundException]){return $true}
            $exception=$exception.InnerException
        }
        return $false
    }
    function Set-PntItemAcl([string]$Path,[bool]$IsDirectory){
        $acl=if($IsDirectory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
        $acl.SetAccessRuleProtection($true,$false)
        $inherit=if($IsDirectory){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
        foreach($sid in @([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),$AdministratorSid)){
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($GroupSid,[Security.AccessControl.FileSystemRights]::Modify,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        # Persist only the DACL. Set-Acl can also attempt to write the SACL and require SeSecurityPrivilege.
        function Write-PntAcl {
            if($IsDirectory){[IO.Directory]::SetAccessControl($Path,$acl)}else{[IO.File]::SetAccessControl($Path,$acl)}
        }
        try {
            try {Write-PntAcl}
            catch [UnauthorizedAccessException] {
                # An elevated repair can recover an item even when its old DACL denied access.
                & takeown.exe /F $Path /A | Out-Null
                if($LASTEXITCODE -ne 0){
                    # Distinguish a vanished temporary file from an ownership failure.
                    [IO.File]::GetAttributes($Path) | Out-Null
                    throw "Cannot take ownership of $Path"
                }
                Write-PntAcl
            }
        }
        catch {if(Test-PntMissingItem $_){return $false};throw}
        return $true
    }
    # Repair each parent before enumerating children with potentially broken inheritance.
    if(-not (Set-PntItemAcl $directory $true)){throw "The PNT data directory disappeared: $directory"}
    $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($directory)
    while($pending.Count -gt 0){
        $current=$pending.Dequeue()
        try{$entries=@(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)}
        catch{if(Test-PntMissingItem $_){continue};throw}
        foreach($entry in $entries){
            if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
            if(-not (Set-PntItemAcl $entry.FullName ([bool]$entry.PSIsContainer))){continue}
            if($entry.PSIsContainer){$pending.Enqueue($entry.FullName)}
            elseif($entry.Name -in @('pnt.db','pnt.db-wal','pnt.db-shm')){
                try{[IO.File]::SetAttributes($entry.FullName,($entry.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)))}
                catch{if(-not (Test-PntMissingItem $_)){throw}}
            }
        }
    }
    $probe=Join-Path $directory ('access-check-'+[guid]::NewGuid().ToString('N'))
    try{$file=[IO.File]::Open($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$file.Dispose()}
    finally{if([IO.File]::Exists($probe)){[IO.File]::Delete($probe)}}
}

function Repair-PntAccess {
    param([Parameter(Mandatory=$true)][string]$DataPath)
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    if(-not $identity.IsSystem -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Repair requires an elevated Administrator terminal.'}
    $group=Get-LocalGroup -Name PNTAdmin -ErrorAction SilentlyContinue
    if(-not $group){$group=New-LocalGroup -Name PNTAdmin -Description 'PNT cluster administrators'}
    Set-PntDirectoryAcl -DataPath $DataPath -GroupSid $group.SID
}
