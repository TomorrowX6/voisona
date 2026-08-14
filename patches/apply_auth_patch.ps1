$exe = Join-Path $PSScriptRoot "VoiSona.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)
# isAuthenticated @ 0x140A01A60, file offset 0xA00E60, 94 bytes
$fo = 0x400 + (0x140A01A60 - 0x140001000)
Write-Output ("file offset: 0x{0:X}" -f $fo)
$orig = ($bytes[$fo..($fo+7)] | ForEach-Object { $_.ToString('X2') }) -join ' '
Write-Output "orig first 8: $orig"
if($orig -ne '48 89 5C 24 08 57 48 83'){ Write-Output "MISMATCH - abort"; exit 1 }
# patch: mov al,1; ret  (B0 01 C3), NOP the rest
$bytes[$fo] = 0xB0; $bytes[$fo+1] = 0x01; $bytes[$fo+2] = 0xC3
for($i=3; $i -lt 0x5E; $i++){ $bytes[$fo+$i] = 0x90 }
[System.IO.File]::WriteAllBytes($exe, $bytes)
$new = ($bytes[$fo..($fo+7)] | ForEach-Object { $_.ToString('X2') }) -join ' '
Write-Output "patched: $new"
Write-Output "isAuthenticated -> always true"
