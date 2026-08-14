$exe = Join-Path $PSScriptRoot "VoiSona.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)
# update check: after isAuthenticated, always jump to "up to date" path
# VA 0x140B3530C: je 0x140B3570D -> jmp 0x140B3570D
$fo = 0x400 + (0x140B3530C - 0x140001000)
Write-Output ("file offset: 0x{0:X}" -f $fo)
$orig = ($bytes[$fo..($fo+5)] | ForEach-Object { $_.ToString('X2') }) -join ' '
Write-Output "orig: $orig"
if($orig -ne '0F 84 FB 03 00 00'){ Write-Output "MISMATCH - abort"; exit 1 }
$bytes[$fo] = 0xE9; $bytes[$fo+1] = 0xFC; $bytes[$fo+2] = 0x03; $bytes[$fo+3] = 0x00; $bytes[$fo+4] = 0x00; $bytes[$fo+5] = 0x90
$new = ($bytes[$fo..($fo+5)] | ForEach-Object { $_.ToString('X2') }) -join ' '
Write-Output "patched: $new"
[System.IO.File]::WriteAllBytes($exe, $bytes)
Write-Output "update check -> always up-to-date (no request, no dialog)"
