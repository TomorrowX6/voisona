$dst = "C:\Program Files\Techno-Speech\VoiSona\VoiSona.exe"
$b = [System.IO.File]::ReadAllBytes($dst)
function HexAt($b, $off, $n){ $s=''; for($i=0;$i -lt $n;$i++){ $s += $b[$off+$i].ToString('X2') + ' ' }; $s.Trim() }
$checks = @(
  @('p1 UI playhead',     0xAFB2B2, 8, '66 0F 2F 05 76 C1 6A 00'),
  @('p2 event case',      0xAF78C5, 3, '83 FA FF'),
  @('p3 engine mulsd',    (0x400+(0x140A7FD77-0x140001000)), 8, 'F2 0F 59 35 B1 82 72 00'),
  @('p4 engine movsd',    (0x400+(0x140A7FFC4-0x140001000)), 8, 'F2 0F 10 05 64 80 72 00'),
  @('p5 engine clamp',    (0x400+(0x140A8017B-0x140001000)), 8, 'F2 0F 10 0D AD 7E 72 00'),
  @('p6 timer mulsd',     (0x400+(0x140A6B9AF-0x140001000)), 8, 'F2 0F 59 05 79 C6 73 00'),
  @('p7 const',           (0x00ee7a00+(0x140FE06F0-0x140ee9000)), 8, '00 00 00 00 00 6A F8 40'),
  @('p8 export include',  (0x400+(0x140B3B63A-0x140001000)), 3, 'B1 01 90'),
  @('p9 render skip',     (0x400+(0x140B07326-0x140001000)), 6, '90 90 90 90 90 90'),
  @('p10 len mulsd',      (0x400+(0x140B0F260-0x140001000)), 8, 'F2 0F 59 05 C8 8D 69 00'),
  @('p11 auth bypass',    (0x400+(0x140A01A60-0x140001000)), 3, 'B0 01 C3'),
  @('p12 update check',   (0x400+(0x140B3530C-0x140001000)), 6, 'E9 FC 03 00 00 90'),
  @('p13 login gate',     (0x400+(0x140B35F3D-0x140001000)), 13, '90 90 90 90 90 90 90 90 90 90 90 90 90'),
  @('p14 list gate1',     (0x400+(0x140B32843-0x140001000)), 9, '90 90 90 90 90 90 90 90 90'),
  @('p14 list gate2',     (0x400+(0x140B3EB38-0x140001000)), 9, '90 90 90 90 90 90 90 90 90'),
  @('p16 IsTrial false',  (0x400+(0x14013D5C0-0x140001000)), 3, '30 C0 C3')
)
$all = $true
foreach($c in $checks){
  $got = HexAt $b $c[1] $c[2]
  $m = ($got -eq $c[3])
  if(-not $m){ $all = $false }
  Write-Output ("{0,-17}: {1}  {2}" -f $c[0], $got, $(if($m){'OK'}else{'MISSING'}))
}
Write-Output ("ALL: {0}" -f $all)