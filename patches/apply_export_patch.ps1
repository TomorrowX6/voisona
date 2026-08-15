$exe = Join-Path $PSScriptRoot "VoiSona.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)
$ok = $true
$TARGET = 0x1411A8030

# #8: export track inclusion: xor cl,1 -> mov cl,1 (always include trial tracks in mixdown)
$fo8 = 0x400 + (0x140B3B63A - 0x140001000)
$o8 = ($bytes[$fo8..($fo8+2)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o8 -ne '80 F1 01'){ Write-Output "MISMATCH #8: $o8"; $ok = $false }
else { $bytes[$fo8]=0xB1; $bytes[$fo8+1]=0x01; $bytes[$fo8+2]=0x90; Write-Output "#8 0x140B3B63A: 80 F1 01 -> B1 01 90" }

# #9: remove trial&&flag render skip: jne -> nops
$fo9 = 0x400 + (0x140B07326 - 0x140001000)
$o9 = ($bytes[$fo9..($fo9+5)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o9 -ne '0F 85 05 03 00 00'){ Write-Output "MISMATCH #9: $o9"; $ok = $false }
else { for($i=0;$i -lt 6;$i++){ $bytes[$fo9+$i]=0x90 }; Write-Output "#9 0x140B07326: jne -> NOPx6" }

# #10: trial length mulsd 10.0 -> 100000.0
$fo10 = 0x400 + (0x140B0F260 - 0x140001000)
$o10 = ($bytes[$fo10..($fo10+7)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o10 -ne 'F2 0F 59 05 88 8B 69 00'){ Write-Output "MISMATCH #10: $o10"; $ok = $false }
else {
  $bytes[$fo10+4]=0xC8; $bytes[$fo10+5]=0x8D; $bytes[$fo10+6]=0x69; $bytes[$fo10+7]=0x00
  $disp = [BitConverter]::ToInt32($bytes, $fo10+4)
  $tgt = (0x140B0F260 + 8) + $disp
  if($tgt -ne $TARGET){ Write-Output "TARGET WRONG: 0x$($tgt.ToString('X'))"; $ok = $false }
  else { Write-Output "#10 0x140B0F260: mulsd -> 100000.0 (target OK)" }
}

if($ok){
  [System.IO.File]::WriteAllBytes($exe, $bytes)
  Write-Output "PATCHES #8-#10 APPLIED"
} else { Write-Output "ABORTED" }

# #16: IsTrial() -> always false (all voices appear as purchased)
# 0x14013D5C0: map-lookup "is voice in trial list" (+ magic hash 0xC48682A2 checks)
$fo16 = 0x400 + (0x14013D5C0 - 0x140001000)
$o16 = ($bytes[$fo16..($fo16+8)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o16 -ne '48 89 5C 24 08 57 48 83 EC'){ Write-Output "MISMATCH #16: $o16"; exit 1 }
else {
  # xor al,al; ret; NOP x6
  $bytes[$fo16]=0x30; $bytes[$fo16+1]=0xC0; $bytes[$fo16+2]=0xC3
  for($i=3;$i -lt 9;$i++){ $bytes[$fo16+$i]=0x90 }
  [System.IO.File]::WriteAllBytes($exe, $bytes)
  Write-Output "#16 0x14013D5C0: IsTrial -> always false (purchased)"
}

# #17: trial-license flag -> 0 (records parsed from trial_licenses marked non-trial)
$fo17 = 0x400 + (0x1409F4425 - 0x140001000)
$o17 = ($bytes[$fo17..($fo17+4)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o17 -ne 'C6 44 24 20 01'){ Write-Output "MISMATCH #17: $o17"; exit 1 }
else {
  $bytes[$fo17+4] = 0x00
  [System.IO.File]::WriteAllBytes($exe, $bytes)
  Write-Output "#17 0x1409F4425: trial_licenses flag 1 -> 0 (badge shows purchased)"
}

# #18: redirect trial_licenses records into the catalog container
# (catalog=main list, trial section ends up empty -> voices appear in main list)
$fo18a = 0x400 + (0x1409F4442 - 0x140001000)
$fo18b = 0x400 + (0x1409F4446 - 0x140001000)
$fo18c = 0x400 + (0x1409F4458 - 0x140001000)
$fo18d = 0x400 + (0x1409F447F - 0x140001000)
$o18a = ($bytes[$fo18a..($fo18a+3)] | ForEach-Object { $_.ToString('X2') }) -join ' '
$o18b = ($bytes[$fo18b..($fo18b+3)] | ForEach-Object { $_.ToString('X2') }) -join ' '
$o18c = ($bytes[$fo18c..($fo18c+6)] | ForEach-Object { $_.ToString('X2') }) -join ' '
$o18d = ($bytes[$fo18d..($fo18d+3)] | ForEach-Object { $_.ToString('X2') }) -join ' '
if($o18a -ne '49 8B 45 38' -or $o18b -ne '49 3B 45 40' -or $o18c -ne '49 81 45 38 A0 00 00' -or $o18d -ne '49 8D 4D 30'){ Write-Output "MISMATCH #18: $o18a/$o18b/$o18c/$o18d"; exit 1 }
else {
  $bytes[$fo18a+3] = 0x20  # [r13+0x38] -> [r13+0x20]
  $bytes[$fo18b+3] = 0x28  # [r13+0x40] -> [r13+0x28]
  $bytes[$fo18c+3] = 0x20  # add [r13+0x38] -> [r13+0x20]
  $bytes[$fo18d+3] = 0x18  # lea [r13+0x30] -> [r13+0x18]
  [System.IO.File]::WriteAllBytes($exe, $bytes)
  Write-Output "#18: trial_licenses -> catalog container (voices in main list, no trial section)"
}




