$exe = Join-Path $PSScriptRoot "VoiSona.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)

function Expect($off, $want, $name) {
  $got = ($bytes[$off..($off+$want.Length-1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
  $wantS = ($want | ForEach-Object { $_.ToString('X2') }) -join ' '
  if($got -ne $wantS){ Write-Output "MISMATCH at $name (0x$('{0:X}' -f $off)): $got"; exit 1 }
  Write-Output "OK $name @ 0x$('{0:X}' -f $off)"
}

# --- p11: isAuthenticated @ 0x140A01A60, file offset 0xA00E60, 94 bytes ---
$fo11 = 0x400 + (0x140A01A60 - 0x140001000)
Expect $fo11 @(0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83) "p11 isAuthenticated"
# patch: mov al,1; ret  (B0 01 C3), NOP the rest
$bytes[$fo11] = 0xB0; $bytes[$fo11+1] = 0x01; $bytes[$fo11+2] = 0xC3
for($i=3; $i -lt 0x5E; $i++){ $bytes[$fo11+$i] = 0x90 }
Write-Output "p11: isAuthenticated -> always true"

# --- p13: fresh-install login screen gate @ 0x140B35F3D ---
# RefreshUI(): if(isAuth && mailStrNotEmpty) showEditor else jmp BuildLoginUI
# p11 makes isAuth always true; p13 NOPs the mail-string emptiness check
# cmp BYTE PTR [rbx+0x36d0],0 / je 0x140b35fe0  (13 bytes) -> NOP x13
$fo13 = 0x400 + (0x140B35F3D - 0x140001000)
Expect $fo13 @(0x80,0xBB,0xD0,0x36,0x00,0x00,0x00,0x0F,0x84,0x96,0x00,0x00,0x00) "p13 login gate"
for($i=0; $i -lt 13; $i++){ $bytes[$fo13+$i] = 0x90 }
Write-Output "p13: fresh-install login screen suppressed (editor path always taken)"

[System.IO.File]::WriteAllBytes($exe, $bytes)
Write-Output "auth patches applied: p11 + p13"
