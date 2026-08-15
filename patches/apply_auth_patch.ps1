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

# --- p14: local voice-list gates @ 0x140B32843 / 0x140B3EB38 ---
# voice list is built by a LOCAL scan of voices\Singer, but two sites gate the
# refresh dispatch on isAuth && mail-nonempty; with p11/p13 we still have no
# mail on a fresh install, so NOP the mail check at both sites:
#   cmp BYTE PTR [x+0x36d0],0 / je skip  (9 bytes each) -> NOP x9
$fo14a = 0x400 + (0x140B32843 - 0x140001000)
$fo14b = 0x400 + (0x140B3EB38 - 0x140001000)
Expect $fo14a @(0x80,0xBB,0xD0,0x36,0x00,0x00,0x00,0x74,0x09) "p14 gate1"
Expect $fo14b @(0x41,0x38,0xB6,0xD0,0x36,0x00,0x00,0x74,0x09) "p14 gate2"
for($i=0; $i -lt 9; $i++){ $bytes[$fo14a+$i] = 0x90; $bytes[$fo14b+$i] = 0x90 }
Write-Output "p14: voice-list refresh runs without mail (local voices listed on fresh install)"

# --- p15 (EXPERIMENTAL, 未完成): embedded default credentials ---
# UpdateLicenseInfo() @ 0x140B36530 skips the login chain when config mail/license
# are empty. p15 overwrites the two local string slots with pointers to embedded
# credentials in .data, so a fresh install (no config.json) auto-logs-in.
# 注意：实测登录请求体中 email/password 序列化不正确（应用的字符串为加密/特殊
# 布局，.data 静态字符串无法直接复用），因此 p15 默认不启用，仅当显式传入
# -Email/-LicenseKey 时应用。当前推荐使用 seed_config.ps1 代替。
if($Email -ne "" -and $LicenseKey -ne ""){
  $dataVMA = 0x14133C000; $dataFO = 0x133a600
  $mailVMA = 0x141345F35
  $licVMA  = 0x141345F35 + 0x50
  function WriteDataStr($vma, [string]$s){
    $fo = $dataFO + ($vma - $dataVMA)
    $enc = [System.Text.Encoding]::ASCII.GetBytes($s)
    if($enc.Length -gt 0x4F){ Write-Output "string too long: $s"; exit 1 }
    # mimic juce String heap layout: refCount @ -0x10, strongRef @ -0xC, length @ -0x8
    [BitConverter]::GetBytes([int]10).CopyTo($bytes, $fo - 0x10)
    [BitConverter]::GetBytes([int]10).CopyTo($bytes, $fo - 0xC)
    [BitConverter]::GetBytes([int64]$enc.Length).CopyTo($bytes, $fo - 0x8)
    $enc.CopyTo($bytes, $fo)
    $bytes[$fo + $enc.Length] = 0
  }
  WriteDataStr $mailVMA $Email
  WriteDataStr $licVMA $LicenseKey

  # patch UpdateLicenseInfo @ 0x140B36578 (30 bytes):
  #   lea rax,[rip+mail]; mov [rbp+0x77],rax   (slot 0x77 -> auth+0x30 = email)
  #   lea rax,[rip+lic];  mov [rbp+0x7F],rax   (slot 0x7f -> auth+0x38 = password)
  #   NOP x8
  $fo15 = 0x400 + (0x140B36578 - 0x140001000)
  Expect $fo15 @(0x48,0x8B,0x45,0x7F,0x80,0x38,0x00,0x0F,0x84,0x3C,0x01,0x00,0x00,0x48,0x8B,0x45,0x77,0x80,0x38,0x00,0x0F,0x84,0x2F,0x01,0x00,0x00,0xC6,0x45,0x70,0x00) "p15 UpdateLicenseInfo gate"
  $dispMail = $mailVMA - (0x140B36578 + 7)
  $dispLic  = $licVMA  - (0x140B36583 + 7)
  $patch15 = @(0x48,0x8D,0x05) + [BitConverter]::GetBytes([int]$dispMail) +
             @(0x48,0x89,0x45,0x77) +
             @(0x48,0x8D,0x05) + [BitConverter]::GetBytes([int]$dispLic) +
             @(0x48,0x89,0x45,0x7F) + @(0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90)
  for($i=0; $i -lt 30; $i++){ $bytes[$fo15+$i] = $patch15[$i] }
  Write-Output "p15: embedded credentials ($Email) - fresh install auto-login"
} else {
  Write-Output "p15 SKIPPED (no -Email/-LicenseKey given)"
}

[System.IO.File]::WriteAllBytes($exe, $bytes)
Write-Output "auth patches applied: p11 + p13 + p14 + p15"
