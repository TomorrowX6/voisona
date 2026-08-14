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
  "source checks: p1=$c1 p8=$c8 p9=$c9" | Out-File $log -Append
  if($c1 -ne '66 0F 2F 05 76 C1 6A 00'){ "abort: p1 wrong" | Out-File $log -Append; exit 1 }
  if($c8 -ne 'B1 01 90'){ "abort: p8 wrong" | Out-File $log -Append; exit 1 }
  if($c9 -ne '90 90 90 90 90 90'){ "abort: p9 wrong" | Out-File $log -Append; exit 1 }

  Copy-Item $src $dst -Force
  "copied" | Out-File $log -Append

  $b2 = [System.IO.File]::ReadAllBytes($dst)
  $hex2 = { param($off,$n) $s=''; for($i=0;$i -lt $n;$i++){ $s += $b2[$off+$i].ToString('X2') + ' ' }; $s.Trim() }
  $v8 = & $hex2 (0x400+(0x140B3B63A-0x140001000)) 3
  $v9 = & $hex2 (0x400+(0x140B07326-0x140001000)) 6
  "deploy done: p8=$v8 p9=$v9" | Out-File $log -Append
  "DEPLOY OK"
} catch {
  "DEPLOY ERROR: $($_.Exception.Message)" | Out-File $log -Append
}
