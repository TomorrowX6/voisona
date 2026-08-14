$exe = Join-Path $PSScriptRoot "VoiSona.exe"
Copy-Item (Join-Path $PSScriptRoot "VoiSona.exe.orig") $exe -Force -ErrorAction SilentlyContinue
$bytes = [System.IO.File]::ReadAllBytes($exe)
$ok = $true
$TARGET = 0x1411A8030

function Apply($bytes, $va, $expectBytes, $newDispBytes){
  $fo = 0x400 + ($va - 0x140001000)
  $n = 8
  $orig = ($bytes[$fo..($fo+$n-1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
  if($orig -ne $expectBytes){
    Write-Output ("MISMATCH @0x{0:X}: got {1} want {2}" -f $va, $orig, $expectBytes)
    $script:ok = $false
    return
  }
  $bytes[$fo+4] = $newDispBytes[0]; $bytes[$fo+5] = $newDispBytes[1]
  $bytes[$fo+6] = $newDispBytes[2]; $bytes[$fo+7] = $newDispBytes[3]
  # verify target
  $disp = [BitConverter]::ToInt32($bytes, $fo+4)
  $tgt = ($va + 8) + $disp
  $okTarget = ($tgt -eq $script:TARGET)
  if(-not $okTarget){ $script:ok = $false }
  Write-Output ("{0:X} : {1} -> {2}  target=0x{3:X} {4}" -f $va, $orig, (($bytes[$fo..($fo+7)] | ForEach-Object { $_.ToString('X2') }) -join ' '), $tgt, $(if($okTarget){'OK'}else{'WRONG'}))
}

Apply $bytes 0x140AFBEB2 '66 0F 2F 05 36 BF 6A 00' @(0x76,0xC1,0x6A,0x00)  # +0x240 = 0x6AC176
Apply $bytes 0x140A7FD77 'F2 0F 59 35 71 80 72 00' @(0xB1,0x82,0x72,0x00)  # +0x240 = 0x7282B1
Apply $bytes 0x140A7FFC4 'F2 0F 10 05 24 7E 72 00' @(0x64,0x80,0x72,0x00)  # +0x240 = 0x728064
Apply $bytes 0x140A8017B 'F2 0F 10 0D 6D 7C 72 00' @(0xAD,0x7E,0x72,0x00)  # +0x240 = 0x727EAD
Apply $bytes 0x140A6B9AF 'F2 0F 59 05 39 C4 73 00' @(0x79,0xC6,0x73,0x00)  # +0x240 = 0x73C679

# patch 2: cmp edx,0xF -> cmp edx,-1
$fo2 = 0x400 + (0x140AF84C5 - 0x140001000)
$o2 = ($bytes[$fo2..($fo2+2)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o2 -ne '83 FA 0F'){ Write-Output "MISMATCH patch2: $o2"; $ok = $false }
else { $bytes[$fo2+2] = 0xFF; Write-Output "AF84C5 : 83 FA 0F -> 83 FA FF" }

# patch 7: const 0x140FE06F0 10.0 -> 100000.0
$rdataFO = 0x00ee7a00; $rdataVMA = 0x140ee9000
$cfo = $rdataFO + (0x140FE06F0 - $rdataVMA)
$co = ($bytes[$cfo..($cfo+7)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($co -ne '00 00 00 00 00 00 24 40'){ Write-Output "MISMATCH const: $co"; $ok = $false }
else {
  $bytes[$cfo+5] = 0x6A; $bytes[$cfo+6] = 0xF8; $bytes[$cfo+7] = 0x40
  Write-Output "const 0x140FE06F0 -> 100000.0"
}

if($ok){
  [System.IO.File]::WriteAllBytes($exe, $bytes)
  Write-Output "ALL PATCHES APPLIED AND TARGET-VERIFIED"
} else {
  Write-Output "ABORTED"
}
