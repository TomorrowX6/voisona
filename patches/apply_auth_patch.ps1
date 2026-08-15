param(
  [string]$Email = "",
  [string]$LicenseKey = ""
)

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
$bytes[$fo11] = 0xB0; $bytes[$fo11+1] = 0x01; $bytes[$fo11+2] = 0xC3
for($i=3; $i -lt 0x5E; $i++){ $bytes[$fo11+$i] = 0x90 }
Write-Output "p11: isAuthenticated -> always true"

# --- p13: fresh-install login screen gate @ 0x140B35F3D ---
$fo13 = 0x400 + (0x140B35F3D - 0x140001000)
Expect $fo13 @(0x80,0xBB,0xD0,0x36,0x00,0x00,0x00,0x0F,0x84,0x96,0x00,0x00,0x00) "p13 login gate"
for($i=0; $i -lt 13; $i++){ $bytes[$fo13+$i] = 0x90 }
Write-Output "p13: fresh-install login screen suppressed (editor path always taken)"

# --- p14: local voice-list gates @ 0x140B32843 / 0x140B3EB38 ---
$fo14a = 0x400 + (0x140B32843 - 0x140001000)
$fo14b = 0x400 + (0x140B3EB38 - 0x140001000)
Expect $fo14a @(0x80,0xBB,0xD0,0x36,0x00,0x00,0x00,0x74,0x09) "p14 gate1"
Expect $fo14b @(0x41,0x38,0xB6,0xD0,0x36,0x00,0x00,0x74,0x09) "p14 gate2"
for($i=0; $i -lt 9; $i++){ $bytes[$fo14a+$i] = 0x90; $bytes[$fo14b+$i] = 0x90 }
Write-Output "p14: voice-list refresh runs without mail (local voices listed on fresh install)"

# --- p15 (EXPERIMENTAL): embedded default credentials ---
# UpdateLicenseInfo @ 0x140B36530 skips login when config mail/license empty.
# p15 overwrites the two string slots with .data pointers so a fresh install
# auto-logs-in. NOTE: the app's string serialization is protected (special
# layout), the login body gets corrupted - p15 is OFF by default; use
# seed_config.ps1 instead. Only applied when -Email/-LicenseKey are passed.
if($Email -ne "" -and $LicenseKey -ne ""){
  $dataVMA = 0x14133C000; $dataFO = 0x133a600
  $mailVMA = 0x141345F35
  $licVMA  = 0x141345F35 + 0x50
  function WriteDataStr($vma, [string]$s){
    $fo = $dataFO + ($vma - $dataVMA)
    $enc = [System.Text.Encoding]::ASCII.GetBytes($s)
    if($enc.Length -gt 0x4F){ Write-Output "string too long: $s"; exit 1 }
    [BitConverter]::GetBytes([int]10).CopyTo($bytes, $fo - 0x10)
    [BitConverter]::GetBytes([int]10).CopyTo($bytes, $fo - 0xC)
    [BitConverter]::GetBytes([int64]$enc.Length).CopyTo($bytes, $fo - 0x8)
    $enc.CopyTo($bytes, $fo)
    $bytes[$fo + $enc.Length] = 0
  }
  WriteDataStr $mailVMA $Email
  WriteDataStr $licVMA $LicenseKey

  $fo15 = 0x400 + (0x140B36578 - 0x140001000)
  Expect $fo15 @(0x48,0x8B,0x45,0x7F,0x80,0x38,0x00,0x0F,0x84,0x3C,0x01,0x00,0x00,0x48,0x8B,0x45,0x77,0x80,0x38,0x00,0x0F,0x84,0x2F,0x01,0x00,0x00,0xC6,0x45,0x70,0x00) "p15 UpdateLicenseInfo gate"
  $dispMail = $mailVMA - (0x140B36578 + 7)
  $dispLic  = $licVMA  - (0x140B36583 + 7)
  $patch15 = @(0x48,0x8D,0x05) + [BitConverter]::GetBytes([int]$dispMail) + @(0x48,0x89,0x45,0x77) + @(0x48,0x8D,0x05) + [BitConverter]::GetBytes([int]$dispLic) + @(0x48,0x89,0x45,0x7F) + @(0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90)
  for($i=0; $i -lt 30; $i++){ $bytes[$fo15+$i] = $patch15[$i] }
  Write-Output "p15: embedded credentials (EXPERIMENTAL, serialization broken)"
} else {
  Write-Output "p15 SKIPPED (no -Email/-LicenseKey given)"
}

[System.IO.File]::WriteAllBytes($exe, $bytes)
Write-Output "auth patches applied: p11 + p13 + p14"
