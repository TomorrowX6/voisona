# seed_config.ps1 - 全新安装时写入 config.json 种子，让声库列表在无登录界面的情况下可用
#
# 原理：VoiSona 的声库列表 = 本地 voices\Singer 目录 + 账号许可信息。
# 应用启动时自动用 mail + license_key（即密码）POST 登录换取 JWT，
# 之后才构建声库列表并为当前声库激活试用。配合 p13（不弹登录界面），
# 在全新机器上放置本脚本生成的 config.json 即可直接进入编辑器并获得完整声库列表。
#
# 用法（仅需执行一次）：
#   powershell -ExecutionPolicy Bypass -File patches\seed_config.ps1 -Email "you@example.com" -LicenseKey "64位hex许可密钥"
param(
  [Parameter(Mandatory=$true)][string]$Email,
  [Parameter(Mandatory=$true)][string]$LicenseKey,
  [string]$HostDir = ""
)
if($HostDir -eq ""){
  $HostDir = Join-Path $env:APPDATA "Techno-Speech\VoiSona\Host"
}
if(-not (Test-Path $HostDir)){ New-Item -ItemType Directory -Path $HostDir -Force | Out-Null }

$configPath = Join-Path $HostDir "config.json"
if(Test-Path $configPath){
  Write-Output "config.json 已存在，跳过（如需覆盖请先删除或移走 Host 目录）"
  exit 0
}

$cfg = @"
{
  "mail": "$Email",
  "license_key": "$LicenseKey",
  "window_state": "fs 373 96 960 720",
  "recent_files": ""
}
"@
[System.IO.File]::WriteAllText($configPath, $cfg)
Write-Output "已写入: $configPath"
Write-Output "下次启动 VoiSona 将自动登录（无登录界面）并加载声库列表。"
