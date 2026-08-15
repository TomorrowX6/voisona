$log = (Join-Path $PSScriptRoot 'deploy_log.txt')
"deploy start $(Get-Date -Format 'HH:mm:ss')" | Out-File $log
try {
  $ErrorActionPreference = 'Stop'
  $src = (Join-Path $PSScriptRoot 'VoiSona.exe')
  $dst = 'C:\Program Files\Techno-Speech\VoiSona\VoiSona.exe'

  $p = Get-Process -Name VoiSona -ErrorAction SilentlyContinue
  if($p){ "aborted: VoiSona running pid $($p.Id)" | Out-File $log -Append; exit 1 }

  $b = [System.IO.File]::ReadAllBytes($src)
  $hex = { param($off,$n) $s=''; for($i=0;$i -lt $n;$i++){ $s += $b[$off+$i].ToString('X2') + ' ' }; $s.Trim() }
  $c1 = & $hex (0xAFB2B2) 8
  $c8 = & $hex (0x400+(0x140B3B63A-0x140001000)) 3
  $c9 = & $hex (0x400+(0x140B07326-0x140001000)) 6
  $c11 = & $hex (0x400+(0x140A01A60-0x140001000)) 3
  $c13 = & $hex (0x400+(0x140B35F3D-0x140001000)) 13
  $c14 = & $hex (0x400+(0x140B32843-0x140001000)) 9
  "source checks: p1=$c1 p8=$c8 p9=$c9 p11=$c11 p13=$c13 p14=$c14" | Out-File $log -Append
  if($c1 -ne '66 0F 2F 05 76 C1 6A 00'){ "abort: p1 wrong" | Out-File $log -Append; exit 1 }
  if($c8 -ne 'B1 01 90'){ "abort: p8 wrong" | Out-File $log -Append; exit 1 }
  if($c9 -ne '90 90 90 90 90 90'){ "abort: p9 wrong" | Out-File $log -Append; exit 1 }
  if($c11 -ne 'B0 01 C3'){ "abort: p11 wrong" | Out-File $log -Append; exit 1 }
  if($c13 -ne '90 90 90 90 90 90 90 90 90 90 90 90 90'){ "abort: p13 wrong" | Out-File $log -Append; exit 1 }
  if($c14 -ne '90 90 90 90 90 90 90 90 90'){ "abort: p14 wrong" | Out-File $log -Append; exit 1 }

  Copy-Item $src $dst -Force
  "copied" | Out-File $log -Append

  $b2 = [System.IO.File]::ReadAllBytes($dst)
  $hex2 = { param($off,$n) $s=''; for($i=0;$i -lt $n;$i++){ $s += $b2[$off+$i].ToString('X2') + ' ' }; $s.Trim() }
  $v8 = & $hex2 (0x400+(0x140B3B63A-0x140001000)) 3
  $v9 = & $hex2 (0x400+(0x140B07326-0x140001000)) 6
  $v11 = & $hex2 (0x400+(0x140A01A60-0x140001000)) 3
  $v13 = & $hex2 (0x400+(0x140B35F3D-0x140001000)) 13
  $v14 = & $hex2 (0x400+(0x140B32843-0x140001000)) 9
  "deploy done: p8=$v8 p9=$v9 p11=$v11 p13=$v13 p14=$v14" | Out-File $log -Append
  "DEPLOY OK"
} catch {
  "DEPLOY ERROR: $($_.Exception.Message)" | Out-File $log -Append
}
